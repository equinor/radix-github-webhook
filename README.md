# radix-github-webhook

Support GitHub Webhook to trigger pipeline build through the API server

## Tips on debugging

Install and run *ngrok* to expose localhost by `ngrok http 3001`. The Webhook in GitHub should point to the *ngrok* address.

## Deployment

Radix GitHub Webhook follows the [standard procedure](https://github.com/equinor/radix-private/blob/master/docs/how-we-work/development-practices.md#standard-radix-applications) defined in *how we work*.

Radix GitHub Webhook is installed as a Radix application in [script](https://github.com/equinor/radix-platform/blob/master/scripts/install_base_components.sh) when setting up a cluster. It will setup app environment with [aliases](https://github.com/equinor/radix-platform/blob/master/scripts/create_alias.sh), and a Webhook so that changes to this repository will be reflected in Radix platform. 

## Manual redeployment on existing cluster

1. Execute `make docker-build`
2. Execute `docker images` to see the imagetag of the last build
3. Execute `az acr login --name radixdev`
4. Execute `docker push radixdev.azurecr.io/radix-github-webhook:<imagetag>` to push the image created in step 1
5. Execute `kubectl edit deploy webhook -n radix-github-webhook-qa`
6. Edit the image name from `radix-github-webhook-webhook` to `radix-github-webhook` and tag from `latest` to `<imagetag>`
7. Save and close
8. Wait for pods to start.
