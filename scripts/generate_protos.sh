#!/bin/bash

DIR=`pwd`
rm -rf $DIR/gen
LYFT_IMAGE="lyft/protocgenerator:d53ce1490e235bf765c93b4a8cfcdd07a1325024"

docker run -u $(id -u):$(id -g) -v $DIR:/defs $LYFT_IMAGE -i ./common/ -d ./common/ -l go --go_source_relative
