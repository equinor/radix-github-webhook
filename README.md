# radix-github-webhook

Support github webhook to trigger pipeline build through the API server

## Tips on debugging

Install and run ngrok to expose localhost by 'ngrok http 3001'. The webhook in github should point to the ngrok adress.

## Manual redeployment on existing cluster

1. Execute `make docker-build`
2. Execute `docker images` to see the imagetag of the last build
3. Execute `az acr login --name radixdev`
4. Execute `docker push radixdev.azurecr.io/radix-github-webhook:<imagetag>` to push the image created in step 1
5. Execute `kubectl edit deploy webhook -n radix-github-webhook-qa`
6. Edit the image name from `radix-github-webhook-webhook` to `radix-github-webhook` and tag from `latest` to `<imagetag>`
7. Save and close
8. Wait for pods to start