module github.com/CiscoAI/kubeflow-scanner

go 1.13

require (
	cloud.google.com/go v0.48.0
	github.com/anchore/kubernetes-admission-controller v0.2.3-0.20191210184938-120f400db688
	github.com/antihax/optional v1.0.0 // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/genuinetools/reg v0.16.1
	github.com/gogo/protobuf v1.3.1 // indirect
	github.com/golang/protobuf v1.3.2
	github.com/googleapis/gnostic v0.3.1 // indirect
	github.com/gorilla/mux v1.7.3
	github.com/json-iterator/go v1.1.8 // indirect
	github.com/konsorten/go-windows-terminal-sequences v1.0.2 // indirect
	github.com/mitchellh/go-wordwrap v1.0.0
	github.com/shurcooL/httpfs v0.0.0-20190707220628-8d4bc4ba7749
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/cobra v0.0.5
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/testify v1.4.0 // indirect
	golang.org/x/crypto v0.0.0-20191011191535-87dc89f01550 // indirect
	golang.org/x/net v0.0.0-20191118183410-d06c31c94cae // indirect
	golang.org/x/sys v0.0.0-20191105231009-c1f44814a5cd // indirect
	google.golang.org/api v0.14.0
	google.golang.org/appengine v1.6.5 // indirect
	google.golang.org/genproto v0.0.0-20191115221424-83cc0476cb11
	google.golang.org/grpc v1.24.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v2 v2.2.7
	k8s.io/api v0.0.0-20190620084959-7cf5895f2711
	k8s.io/apimachinery v0.0.0-20191028221656-72ed19daf4bb
	k8s.io/client-go v11.0.0+incompatible
	k8s.io/klog v1.0.0 // indirect
)

replace k8s.io/client-go => k8s.io/client-go v0.0.0-20190620085101-78d2af792bab
