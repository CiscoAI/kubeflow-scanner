module github.com/CiscoAI/kubeflow-scanner

go 1.13

require (
	cloud.google.com/go v0.48.0
	github.com/NYTimes/openapi2proto v0.2.2 // indirect
	github.com/anchore/kubernetes-admission-controller v0.2.3-0.20191210184938-120f400db688
	github.com/antihax/optional v1.0.0
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/docker/cli v0.0.0-20191220145525-ba63a92655c0 // indirect
	github.com/dolmen-go/jsonptr v0.0.0-20190605225012-a9a7ae01cd7d // indirect
	github.com/fatih/color v1.9.0 // indirect
	github.com/gogo/protobuf v1.3.1 // indirect
	github.com/golang/protobuf v1.3.2
	github.com/google/go-cmp v0.3.1 // indirect
	github.com/google/go-containerregistry v0.0.0-20191218175032-34fb8ff33bed
	github.com/googleapis/gnostic v0.3.1 // indirect
	github.com/googleapis/gnostic-go-generator v0.0.0-20190702052424-e56fb2f7e21c // indirect
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/cobra v0.0.5
	golang.org/x/net v0.0.0-20191118183410-d06c31c94cae // indirect
	golang.org/x/sync v0.0.0-20190911185100-cd5d95a43a6e // indirect
	golang.org/x/tools v0.0.0-20191213221258-04c2e8eff935 // indirect
	google.golang.org/api v0.14.0
	google.golang.org/appengine v1.6.5 // indirect
	google.golang.org/genproto v0.0.0-20191115221424-83cc0476cb11
	gopkg.in/src-d/go-parse-utils.v1 v1.1.2 // indirect
	gopkg.in/src-d/proteus.v1 v1.3.3 // indirect
	gopkg.in/urfave/cli.v1 v1.20.0 // indirect
	gopkg.in/yaml.v2 v2.2.7
	k8s.io/api v0.0.0-20190620084959-7cf5895f2711
	k8s.io/apimachinery v0.0.0-20191028221656-72ed19daf4bb
	k8s.io/client-go v11.0.0+incompatible
	sigs.k8s.io/kind v0.6.0
)

replace k8s.io/client-go => k8s.io/client-go v0.0.0-20190620085101-78d2af792bab
