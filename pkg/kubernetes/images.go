package kubernetes

import (
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func PodLister(namespace string) ([]v1.Pod, error) {
	clientset, err := ClientSetFromKubeconfig()
	if err != nil {
		return []v1.Pod{}, err
	}
	// Fetch all pods in the namespace
	pods, err := clientset.CoreV1().Pods(namespace).List(metav1.ListOptions{})
	if err != nil {
		return []v1.Pod{}, err
	}
	return pods.Items, nil
}

func ImageLister(namespace string) ([]string, error) {
	images := []string{}
	pods, err := PodLister(namespace)
	if err != nil {
		return images, err
	}
	log.Infof("Pods to be scanned:")
	log.Infof("-----------------------")
	for _, pod := range pods {
		log.Infof("Pod name: %v", pod.Name)
		images = append(images, PodImages(pod)...)
	}
	log.Infof("-----------------------")
	return images, nil
}

func PodImages(pod v1.Pod) []string {
	images := []string{}
	log.Infof("    Images to be scanned:")
	log.Infof("-----------------------")
	for _, ic := range pod.Spec.InitContainers {
		if ic.Image != "" {
			log.Infof("    Image name: %v", ic.Image)
			images = append(images, ic.Image)
		}
	}
	for _, c := range pod.Spec.Containers {
		if c.Image != "" {
			log.Infof("    Image name: %v", c.Image)
			images = append(images, c.Image)
		}
	}
	log.Infof("-----------------------")
	return images
}

func removeDuplicates(images []string) error {

	return nil
}
