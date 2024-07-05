# 概要

AxumでJWT認証を実装

## リクエスト例

```
curl -s \
     -w '\n' \
     -H 'Content-Type: application/json' \
     -d '{"client_id":"foo","client_secret":"bar"}' \
     http://localhost:3000/authorize
```

```
curl -s \
    -w '\n' \
    -H 'Content-Type: application/json' \
    -H 'Authorization: Bearer token' \
    http://localhost:3000/protected
```

# 参考

https://github.com/tokio-rs/axum/tree/main/examples/jwt