# DivX PDQ & TMK+PDQF Hash Docker Image

This repository aims to create a usable docker image for the video (TMK+PDQF) and image (PDQ) hashing contained under the ThreatExchange directory, which is a fork of the [Facebook Threat Exchange Github Repository](https://github.com/facebook/ThreatExchange). 

## Building the image
Make sure you are in the root directory where the Dockerfile is located.
Run:
`docker build -t ubuntu-threatexchange .`
You can substitute `ubuntu-threatexchange` for whichever image name you prefer.

## Running the image in Windows
After you have built the docker image, if in a Windows environment run:
`winpty docker run -i -t ubuntu-threatexchange`
Make sure the image name you provide is the same as what you supplied when building the image.

## Testing Image Hashing

The `./pdq-photo-hasher` command can be run inside the docker image in order to test the PDQ Image Hashing ( Perceptual hasher with Discrete cosine transform and an output containing Quality metric or PDQ ). The command can be found in the `/pdq/cpp` directory. Supply the command with an image file path for hashing. An example command is shown below:
```
./pdq-photo-hasher ./images/chair-grey-scale-title.png
```

## Testing Image Comparison
The `./hashtool256` command can be run inside the docker image in order to test the distance generation using PDQ's Hash256 class. The command can be found in the `/pdq/cpp` directory. Provide the command with a verb indicating the type of distance being generated, use `pairwise-distances` in order to simply xor each position of the two hashes. An example command is shown below:
```
./hashtool256 pairwise-distances ./hashes/chair-grey-scale-title ./hashes/chair-sepia-title
```
Something to note, the `./hashtool256` command expects files containing hashes as an input. If the `./pdq-photo-hasher` command above was ran, the printed output will state the photo hash which can then be stored in a file to input into the `./hashtool256` command.

## Testing Video Hashing

The `./tmk-hash-video` command can be run inside the docker image in order to test the Temporal Match Kernel (TMK) Video Hashing. The command can be found in the `/tmk/cpp` directory. Supply the command with the ffmpeg path, video path, the directory in which to write the output hash and optional verbosity. An example command is shown below:
```
./tmk-hash-video -f /usr/bin/ffmpeg -i ../sample-videos/5_MIN_JB.mp4 -d ../sample-hashes -v
```

## Testing Video Comparison

The `./tmk-compare-two-tmks`ommand can be run inside the docker image in order to test the Temporal Match Kernel (TMK) Video Comparison. The command can be found in the `/tmk/cpp` directory. Supply the command with the two tmk file paths and optional verbosity. An example command is shown below:
```
./tmk-compare-two-tmks -v ../sample-hashes/5_MIN_JB.tmk ../sample-hashes/5_MIN_JB_FFMPEG.tmk
```