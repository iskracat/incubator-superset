context = beedata
namespace = dev
FILE_VERSION = ./VERSION
version = $(shell cat $(FILE_VERSION))

purge-superset:
	helm del --kube-context $(context) --purge superset-bee

deploy-superset:
	sed -i.bak 's#99999.99999.99999#$(version)#' ./superset/Chart.yaml
	helm package ./superset
	helm install -n superset-bee ./superset-$(version).tgz --namespace $(namespace)
	sed -i.bak 's#$(version)#99999.99999.99999#' ./superset/Chart.yaml

rollback-superset:
	sed -i.bak 's#99999.99999.99999#$(version)#' ./superset/Chart.yaml
	helm package ./superset
	helm upgrade --install --kube-context $(context) superset-bee ./superset-$(version).tgz
	sed -i.bak 's#$(version)#99999.99999.99999#' ./superset/Chart.yaml

deploy-redis:
	helm install --name redis-bee stable/redis --values ./redis/values.yaml
