# radix-github-webhook

Support GitHub Webhook to trigger pipeline build through the API server

## Development

[Github webhook development docs](https://docs.github.com/en/developers/webhooks-and-events/webhooks/about-webhooks)

[Github webhook integration best practices](https://docs.github.com/en/github-ae@latest/rest/guides/best-practices-for-integrators#use-appropriate-http-status-codes-when-responding-to-github)

## Contribution

Want to contribute? Read our [contributing guidelines](./CONTRIBUTING.md)

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
8. Wait for pods to start

## Authentication

Bearer token can be provided in two ways

* In a file `/var/run/secrets/kubernetes.io/serviceaccount/token`
* Environment variable `BEARER_TOKEN` (create new token with `kubectl create token --namespace radix-github-webhook-qa radix-github-webhook`)

if file does not exist - environment variable has being used

## Debugging

When debug locally together with other apps and services - local `radix-api` can be used
* `USE_LOCAL_RADIX_API`
  * `false`, `no` or not set - connecting to in-cluster `radix-api`
  * `true` or `yes` - connecting to `radix-api`, running on `http://localhost:3002`

## Configuration:

### Commandline arguments: 
- `--port`/ `-p`: Port to listen for, defaults to 3001.

### Environment variables used:
- `USE_LOCAL_RADIX_API`: Defaults to `no`, ex: `no` or `yes`
- `API_SERVER_ENDPOINT_PREFIX`: No defaults, ex: `https://server-radix-api-qa` 
- `RADIX_CLUSTERNAME`: No defaults, ex: `dev` 
- `RADIX_DNS_ZONE`: No defaults, ex: `radix.equinor.com`

## Security

This is how we handle [security issues](./SECURITY.md)