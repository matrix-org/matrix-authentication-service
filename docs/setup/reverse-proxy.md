# Configuring a reverse proxy

Although the service can be exposed directly to the internet, including handling the TLS termination, many deployments will want to run a reverse proxy in front of the service.

In those configuration, the service should be configured to listen on `localhost` or Unix domain socket.

## Example configuration

```yaml
http:
  public_base: https://auth.example.com/
  listeners:
    - name: web
      resources:
        - name: discovery
        - name: human
        - name: oauth
        - name: compat
        - name: graphql
        # Uncomment to serve the assets by the service
        #- name: assets
        #  path: ./share/assets/

      binds:
        # Bind on a local port
        - host: localhost
          port: 8080
          
        # OR bind on a Unix domain socket
        #- socket: /var/run/mas.sock

      # Optional: use the PROXY protocol
      #proxy_protocol: true
```

## Example nginx configuration

Note that the assets can be served directly by nginx, and the `assets` resource can be removed from the service configuration.

```nginx
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name auth.example.com;

    ssl_certificate path/to/fullchain.pem;
    ssl_certificate_key path/to/privkey.pem;

    location / {
        proxy_pass http://localhost:8080;
        # OR via the Unix domain socket
        #proxy_pass http://unix:/var/run/mas.sock;
        
        proxy_http_version 1.1;

        # Optional: use the PROXY protocol
        #proxy_protocol on;
    }
    
    # Optional: serve the assets directly
    location /assets/ {
        root /path/to/share/assets/;
        
        # Serve pre-compressed assets
        gzip_static on;
        # With the ngx_brotli module installed
        # https://github.com/google/ngx_brotli
        #brotli_static on;
        
        # Cache assets for a year
        expires 365d;
    }
}
```

For the compatibility layer, the following endpoints need to be proxied to the service:

 - `/_matrix/client/*/login`
 - `/_matrix/client/*/logout`
 - `/_matrix/client/*/refresh`

For example, a nginx configuration could look like:

```nginx
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    server_name matrix.example.com;
    
    # Forward to the auth service
    location ~ ^/_matrix/client/(.*)/(login|logout|refresh) {
        proxy_pass http://localhost:8080;
        # OR via the Unix domain socket
        #proxy_pass http://unix:/var/run/mas.sock;
        
        proxy_http_version 1.1;

        # Optional: use the PROXY protocol
        #proxy_protocol on;
    }

    # Forward to Synapse
    # as per https://matrix-org.github.io/synapse/latest/reverse_proxy.html#nginx
    location ~ ^(/_matrix|/_synapse/client) {
        proxy_pass http://localhost:8008;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $host;

        client_max_body_size 50M;
        proxy_http_version 1.1;
    }
}
```