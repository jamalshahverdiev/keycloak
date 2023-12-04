# Create container with Jenkins and run it on port 9090

```bash
$ docker build -t jamalshahverdiev/delegatevs:jsv0.0.3 .
$ docker push jamalshahverdiev/delegatevs:jsv0.0.3 
$ docker container run -itd --name=jenkins -p 9090:8080 jamalshahverdiev/delegatevs:jsv0.0.3
```