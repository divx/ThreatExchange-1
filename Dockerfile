FROM ubuntu:20.04

# set time zone so tzdata does not hang
# ENV TZ=America
# RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# install build dependencies
RUN apt-get update && apt-get install -y g++ ffmpeg vim
RUN apt-get install -y cmake
RUN apt-get install -y imagemagick

ADD ./ /

RUN cd ./tmk/cpp && make

RUN cd ./pdq/cpp && make
