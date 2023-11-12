

#### Get `Access_Token` (`t.owen` is member of `Admin` Role) for the user with administrator privileges

```bash
$ ACCESS_TOKEN=$(curl -s -X POST http://10.100.100.100:8080/realms/infra/protocol/openid-connect/token -d 'client_id=grafana-oauth' -d 'client_secret=Bz1RvkrW0KyPnpADp5yLU15JuYFXazfI' -d 'username=t.owen' -d 'password=Foo_b_ar123!' -d 'grant_type=password' | jq -r '.access_token')
```

#### Get User information with Access token (Look at the roles membership is `admin`):

```bash
$ curl -s -X POST http://10.100.100.100:8080/realms/infra/protocol/openid-connect/userinfo -H "Authorization: Bearer $ACCESS_TOKEN" | jq
{
  "sub": "faa4d256-287c-4e50-a985-efbe8bf62c1d",
  "email_verified": false,
  "realm_access": {
    "roles": [
      "offline_access",
      "uma_authorization",
      "default-roles-infra",
      "Admin"
    ]
  },
  "name": "Tillie Owen",
  "preferred_username": "t.owen",
  "given_name": "Tillie",
  "family_name": "Owen",
  "email": "t.owen@example.com"
}
```


#### Get `Access_Token` (`r.cockshutt` is member of the `Viewer` Role) for the user with viewer privileges

```bash
$ ACCESS_TOKEN=$(curl -s -X POST http://10.100.100.100:8080/realms/infra/protocol/openid-connect/token -d 'client_id=grafana-oauth' -d 'client_secret=Bz1RvkrW0KyPnpADp5yLU15JuYFXazfI' -d 'username=r.cockshutt' -d 'password=Foo_b_ar123!' -d 'grant_type=password' | jq -r '.access_token')
```

#### Get User information with Access token (Look at the roles membership is `Viewer`):

```bash
$ curl -s -X POST http://10.100.100.100:8080/realms/infra/protocol/openid-connect/userinfo -H "Authorization: Bearer $ACCESS_TOKEN" | jq
{
  "sub": "64a288a3-ec1a-4029-8b6b-bee6162fe3e7",
  "email_verified": false,
  "realm_access": {
    "roles": [
      "offline_access",
      "Viewer",
      "uma_authorization",
      "default-roles-infra"
    ]
  },
  "name": "Roxane Cockshutt",
  "preferred_username": "r.cockshutt",
  "given_name": "Roxane",
  "family_name": "Cockshutt",
  "email": "r.cockshutt@example.com"
}
```
