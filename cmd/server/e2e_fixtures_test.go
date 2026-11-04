package main

import (
	"github.com/sanskarpan/Ghostlight/internal/passport"
	"github.com/sanskarpan/Ghostlight/internal/reviewer"
)

func roomPtr() *reviewer.Room         { return &reviewer.Room{} }
func passportPtr() *passport.Registry { return &passport.Registry{} }
