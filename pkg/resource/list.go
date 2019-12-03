package resource

import (
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/google"
	log "github.com/sirupsen/logrus"
)

var imageList []string

// from gcrane ls function

// GetResourcesFromRepo gets a set of resources from the given repo
func GetResourcesFromRepo(repoName string, recursive bool) ([]string, error) {
	// Fetch repo from repoName
	repo, err := name.NewRepository(repoName)
	if err != nil {
		return nil, fmt.Errorf("error getting repo from repo name: %v", err)
	}

	if recursive {
		if err := google.Walk(repo, appendImages, google.WithAuthFromKeychain(google.Keychain)); err != nil {
			return nil, err
		}
		return imageList, nil
	}

	log.Infof("Fetching resources for repo: %v", repo.Name())
	// TODO(swiftdiaries):: logic for fetching recursively from repo

	// Get tags for repo
	tags, err := google.List(repo, google.WithAuthFromKeychain(google.Keychain))
	if err != nil {
		return nil, fmt.Errorf("error getting tags for repo: %v", err)
	}

	log.Infof("Total manifests for repo: %v", len(tags.Manifests))
	log.Infof("Total children for tags: %v", len(tags.Children))
	if len(tags.Manifests) == 0 && len(tags.Children) == 0 {
		for _, tag := range tags.Tags {
			imageList = append(imageList, fmt.Sprintf("%s:%s", repo, tag))
		}
		return imageList, nil
	}
	for _, child := range tags.Children {
		imageList = append(imageList, fmt.Sprintf("%s:%s", repo, child))
	}

	if err := appendImages(repo, tags, err); err != nil {
		return nil, err
	}

	return imageList, nil
}

// appendImages adds images from repo to list of strings
func appendImages(repo name.Repository, tags *google.Tags, err error) error {
	if err != nil {
		return err
	}

	for digest, manifest := range tags.Manifests {
		imageList = append(imageList, fmt.Sprintf("https://%s@%s", repo, digest))

		for _, tag := range manifest.Tags {
			imageList = append(imageList, fmt.Sprintf("https://%s:%s", repo, tag))
		}
	}
	return nil
}
