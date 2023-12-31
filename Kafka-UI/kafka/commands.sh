helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update

helm search repo bitnami/kafka --versions
helm show values bitnami/kafka --version 26.5.0 > kafka-values.yaml
# helm install kafka bitnami/kafka --create-namespace --namespace kafka 
helm install kafka bitnami/kafka --create-namespace --namespace kafka -f values.yaml
