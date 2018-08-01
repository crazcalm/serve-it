# Serve-It
[![Go Report Card](https://goreportcard.com/badge/github.com/crazcalm/serve-it)](https://goreportcard.com/report/github.com/crazcalm/serve-it)

A command line application that allows you to run a file server on local host that hides dot files.

## Note:
I am keeping this repository around as reference to a talk I gave at a meetup and a blog post I wrote about it. Since then, I have learned the proper way to create a custom File Server. I outline these new insights in the following blog post: [Using Embedding to Create a Custom File Server](https://crazcalm.github.io/blog/post/custom_file_server/).

If you still want the functionality of Serve-It and would like to see what it looks like rewritten using embedding, see the following link ([source code](https://github.com/crazcalm/my-go-questions/blob/master/what_if/http.fileServer/hide_dot_files.go)).

## Installation
1. `go get github.com/crazcalm/serve-it`
2. cd into that directory and run `go build`

## Usage

![](img/serve-it.png)
