# Oddities with MAS

## general

After initialising the pod you need to sync MAS with it's config

```bash
kubectl exec -it -n mas deployments/mas -- mas-cli config sync
```

otherwise you'll run into issues with synapse reporting "*unable to introspect token*" and MAS complaining about not knowing about the configured `client_id`s

## migrating users from synapse db to mas

you need to run the tool `syn2mas` which isn't at all included in the mas itself. 
While an container exits for it it's still quite difficult to use.

- You're much quicker by spawning up a container such as
```bash
kubectl run -i --tty --rm debug --image=node:lts --restart=Never -- bash
```
- add your homeserver.yaml and mas config.yaml
- install the `syn2mas`
```bash
npx @matrix-org/syn2mas
```
- run preadvisor **or**
```bash
npx @matrix-org/syn2mas --command=advisor --synapseConfigFile homeserver.yaml
```
- run migration
```bash
npx @matrix-org/syn2mas --command=migrate --synapseConfigFile homeserver.yaml --masConfigFile config.yaml
```

## troubleshooting

mas offers a diagnostic tool which is rather help full, you can run it with
```bash
kubectl exec -it -n mas deployments/mas -- mas-cli doctor
```
