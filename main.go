package main

import (
	"flag"
	"github.com/Sirupsen/logrus"
	"github.com/statoil/radix-webhook/handler"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	// Force loading of needed authentication library
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"net/http"
	"os"
)

func main() {
	var (
		kubeconfig            string
		secret                string
		port                  string
		pipelineHandlerConfig handler.Config
	)

	flag.StringVar(&kubeconfig, "kubeconfig", defaultKubeConfig(), "Absolute path to the kubeconfig file")
	flag.StringVar(&secret, "webhook-secret", defaultSecret(), "Secret defined in web-hook")
	flag.StringVar(&port, "listener-port", defaultPort(), "The port for which we listen to events on")
	flag.StringVar(&pipelineHandlerConfig.Namespace, "namespace", defaultNamespace(), "Kubernetes namespace")
	flag.StringVar(&pipelineHandlerConfig.DockerRegistryPath, "docker-registry", defaultDockerRegistryPath(), "Private docker registry path")
	flag.StringVar(&pipelineHandlerConfig.WorkerImage, "worker-image", defaultWorkerImage(), "Kubernetes worker image")
	flag.StringVar(&pipelineHandlerConfig.RadixConfigBranch, "radix-config-branch", defaultConfigBranch(), "Branch name to pull radix config from")

	client, err := getKubernetesClient(kubeconfig)
	if err != nil {
		logrus.Fatalf("Unable to obtain kubernetes client: %v", err)
	}

	http.ListenAndServe(port, WebhookLog(secret, client, &pipelineHandlerConfig))
}

func WebhookLog(secret string, kubeclient *kubernetes.Clientset, config *handler.Config) http.Handler {
	var p handler.WebhookListener
	p = handler.NewPipelineController(kubeclient, config)
	return handler.HandleWebhookEvents(secret, p)
}

func getKubernetesClient(kubeConfigPath string) (*kubernetes.Clientset, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		config, err = rest.InClusterConfig()
		if err != nil {
			logrus.Fatalf("getClusterConfig InClusterConfig: %v", err)
		}
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		logrus.Fatalf("getClusterConfig k8s client: %v", err)
	}

	return client, err
}

func defaultKubeConfig() string {
	return os.Getenv("HOME") + "/.kube/config"
}

func defaultNamespace() string {
	return corev1.NamespaceDefault
}

func defaultConfigBranch() string {
	return "master"
}

func defaultDockerRegistryPath() string {
	return "radixdev.azurecr.io"
}

func defaultWorkerImage() string {
	return "pipeline-runner"
}

func defaultSecret() string {
	return "AnySecret"
}

func defaultPort() string {
	return ":8001"
}
