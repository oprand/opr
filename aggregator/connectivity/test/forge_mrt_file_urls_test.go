package main

import (
	"github.com/oprand/opr/aggregator/connectivity"
	"github.com/oprand/opr/internal/opbgp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var testUrls = []struct {
	Desc        string
	BgpLocation opbgp.BgpLocation
	Time        time.Time
	ExpectedUrl string
}{
	{
		Desc:        "jan 1st, midnight - right hour but too soon",
		BgpLocation: opbgp.BgpLocation{Slug: "foo"},
		Time:        time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		ExpectedUrl: "https://archive.routeviews.org/foo/bgpdata/2023.12/RIBS/rib.20231231.2200.bz2",
	},
	{
		Desc:        "jan 1st, 1am -- wrong hour too soon",
		BgpLocation: opbgp.BgpLocation{Slug: "foo"},
		Time:        time.Date(2024, 1, 1, 1, 0, 0, 0, time.UTC),
		ExpectedUrl: "https://archive.routeviews.org/foo/bgpdata/2024.01/RIBS/rib.20240101.0000.bz2",
	},
	{
		Desc:        "odd hour, zero minute -- wrong hour, too soon",
		BgpLocation: opbgp.BgpLocation{Slug: "foo-bar"},
		Time:        time.Date(2024, 1, 10, 7, 0, 0, 0, time.UTC),
		ExpectedUrl: "https://archive.routeviews.org/foo-bar/bgpdata/2024.01/RIBS/rib.20240110.0600.bz2",
	},
	{
		Desc:        "odd hour, 16 minutes -- wrong hour, not soon",
		BgpLocation: opbgp.BgpLocation{Slug: "foo"},
		Time:        time.Date(2024, 12, 31, 7, 16, 0, 0, time.UTC),
		ExpectedUrl: "https://archive.routeviews.org/foo/bgpdata/2024.12/RIBS/rib.20241231.0600.bz2",
	},
	{
		Desc:        "even hour -- good hour not soon",
		BgpLocation: opbgp.BgpLocation{Slug: "foo"},
		Time:        time.Date(2024, 12, 31, 8, 59, 0, 0, time.UTC),
		ExpectedUrl: "https://archive.routeviews.org/foo/bgpdata/2024.12/RIBS/rib.20241231.0800.bz2",
	},
	{
		Desc:        "even hour -- good hour too soon",
		BgpLocation: opbgp.BgpLocation{Slug: "foo"},
		Time:        time.Date(2024, 12, 31, 8, 3, 0, 0, time.UTC),
		ExpectedUrl: "https://archive.routeviews.org/foo/bgpdata/2024.12/RIBS/rib.20241231.0600.bz2",
	},
}

func TestForgeMtrFileUrl(t *testing.T) {

	for _, input := range testUrls {

		t.Run(input.Desc, func(t *testing.T) {

			t.Log(input.Time.String())

			url := connectivity.ForgeMtrFileUrl(&input.BgpLocation, input.Time)

			assert.Equalf(t, input.ExpectedUrl, url, "urls not equal")

		})

	}

}
