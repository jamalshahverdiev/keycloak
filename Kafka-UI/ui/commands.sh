helm repo add kafka-ui https://provectus.github.io/kafka-ui-charts
helm install kafka-ui kafka-ui/kafka-ui --namespace kafka --create-namespace -f values.yaml
# helm install kafka-ui kafka-ui/kafka-ui --namespace kafka --create-namespace --set yamlApplicationConfigConfigMap.name="kafka-ui-configmap",yamlApplicationConfigConfigMap.keyName="config.yml"
