package handler

import (
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/google/go-github/github"
	"github.com/pkg/errors"
	"github.com/thanhpk/randstr"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"net/http"
	"strings"
	"time"
)

type Config struct {
	Namespace          string
	DockerRegistryPath string
	WorkerImage        string
	RadixConfigBranch  string
}

type PipelineTrigger struct {
	kubeclient *kubernetes.Clientset
	config     *Config
}

func (p *PipelineTrigger) ProcessPingEvent(pingEvent *github.PingEvent, req *http.Request) (string, error) {
	return "Ping received and a corresponding radix application was found", nil
}

func (p *PipelineTrigger) ProcessPullRequestEvent(prEvent *github.PullRequestEvent, req *http.Request) error {
	return errors.New("Pull request is not supported at this moment")
}

func (p *PipelineTrigger) ProcessPushEvent(pushEvent *github.PushEvent, req *http.Request) error {
	jobName := getUniqueJobName(p.config.WorkerImage)
	job := p.createPipelineJob(jobName, *pushEvent.Repo.SSHURL)

	logrus.Infof("Starting pipeline: %s, %s", jobName, p.config.WorkerImage)
	job, err := p.kubeclient.BatchV1().Jobs(p.config.Namespace).Create(job)
	if err != nil {
		logrus.Fatalf("Start pipeline: %v", err)
	}

	jobsSelector := labels.SelectorFromSet(labels.Set(map[string]string{"job_label": jobName})).String()
	optionsModifer := func(options *metav1.ListOptions) {
		options.LabelSelector = jobsSelector
	}

	watchList := cache.NewFilteredListWatchFromClient(p.kubeclient.BatchV1().RESTClient(), "jobs", p.config.Namespace,
		optionsModifer)
	_, controller := cache.NewInformer(
		watchList,
		&batchv1.Job{},
		time.Second*30,
		cache.ResourceEventHandlerFuncs{
			UpdateFunc: handleJobUpdate,
		},
	)

	stop := make(chan struct{})
	go controller.Run(stop)
	return nil
}

func NewPipelineController(kubeclient *kubernetes.Clientset, config *Config) *PipelineTrigger {
	return &PipelineTrigger{
		kubeclient,
		config,
	}
}

func (p *PipelineTrigger) createPipelineJob(jobName, sshUrl string) *batchv1.Job {
	gitCloneCommand := fmt.Sprintf("git clone %s -b %s .", sshUrl, p.config.RadixConfigBranch)
	imageTag := fmt.Sprintf("%s/%s:%s", p.config.DockerRegistryPath, p.config.WorkerImage, "latest")
	logrus.Infof("Using image: %s, %s", imageTag)

	backOffLimit := int32(4)
	defaultMode := int32(256)

	job := batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name: jobName,
			Labels: map[string]string{
				"job_label": jobName,
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit: &backOffLimit,
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{
							Name:    "clone",
							Image:   "alpine:3.7",
							Command: []string{"/bin/sh", "-c"},
							Args:    []string{fmt.Sprintf("apk add --no-cache bash openssh-client git && ls /root/.ssh && cd /workspace && %s", gitCloneCommand)},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "build-context",
									MountPath: "/workspace",
								},
								{
									Name:      "git-ssh-keys",
									MountPath: "/root/.ssh",
									ReadOnly:  true,
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:  p.config.WorkerImage,
							Image: imageTag,
							Args: []string{
								fmt.Sprintf("BRANCH=%s", "master"),
								fmt.Sprintf("RADIX_FILE_NAME=%s", "/workspace/radixconfig.yaml"),
								fmt.Sprintf("IMAGE_TAG=%s", ""),
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "build-context",
									MountPath: "/workspace",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "build-context",
						},
						{
							Name: "git-ssh-keys",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName:  "git-ssh-keys",
									DefaultMode: &defaultMode,
								},
							},
						},
					},
					// https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/
					ImagePullSecrets: []corev1.LocalObjectReference{
						{
							Name: "regcred",
						},
					},
					RestartPolicy: "Never",
				},
			},
		},
	}

	return &job
}

func getUniqueJobName(image string) string {
	var jobName []string
	jobName = append(jobName, image)
	jobName = append(jobName, "-")
	jobName = append(jobName, getCurrentTimestamp())
	jobName = append(jobName, "-")
	jobName = append(jobName, strings.ToLower(randstr.String(5)))
	return strings.Join(jobName, "")
}

func getCurrentTimestamp() string {
	t := time.Now()
	return t.Format("20060102150405") // YYYYMMDDHHMISS in Go
}

func handleJobUpdate(old, current interface{}) {
	oldJob := old.(*batchv1.Job)
	currentJob := current.(*batchv1.Job)

	// Only when old job differs from current job, will we have a state change
	if oldJob != currentJob {
		if currentJob.Status.Succeeded == 1 {
			logrus.Infof("Pipeline job [%s] succeeded", currentJob.Name)
		}
		if currentJob.Status.Failed == 1 {
			logrus.Infof("Pipeline job [%s] failed", currentJob.Name)
		}
	}
}