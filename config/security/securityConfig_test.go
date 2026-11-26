// Copyright 2018 The Hugo Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package security

import (
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/gohugoio/hugo/config"
)

func TestDecodeConfigFromTOML(t *testing.T) {
	c := qt.New(t)

	c.Run("Slice whitelist", func(c *qt.C) {
		c.Parallel()
		tomlConfig := `


someOtherValue = "bar"

[security]
enableInlineShortcodes=true
[security.exec]
allow=["a", "b"]
osEnv=["a", "b", "c"]
[security.funcs]
getEnv=["a", "b"]

`

		cfg, err := config.FromConfigString(tomlConfig, "toml")
		c.Assert(err, qt.IsNil)

		pc, err := DecodeConfig(cfg)
		c.Assert(err, qt.IsNil)
		c.Assert(pc, qt.Not(qt.IsNil))
		c.Assert(pc.EnableInlineShortcodes, qt.IsTrue)
		c.Assert(pc.Exec.Allow.Accept("a"), qt.IsTrue)
		c.Assert(pc.Exec.Allow.Accept("d"), qt.IsFalse)
		c.Assert(pc.Exec.OsEnv.Accept("a"), qt.IsTrue)
		c.Assert(pc.Exec.OsEnv.Accept("e"), qt.IsFalse)
		c.Assert(pc.Funcs.Getenv.Accept("a"), qt.IsTrue)
		c.Assert(pc.Funcs.Getenv.Accept("c"), qt.IsFalse)
	})

	c.Run("String whitelist", func(c *qt.C) {
		c.Parallel()
		tomlConfig := `


someOtherValue = "bar"

[security]
[security.exec]
allow="a"
osEnv="b"

`

		cfg, err := config.FromConfigString(tomlConfig, "toml")
		c.Assert(err, qt.IsNil)

		pc, err := DecodeConfig(cfg)
		c.Assert(err, qt.IsNil)
		c.Assert(pc, qt.Not(qt.IsNil))
		c.Assert(pc.Exec.Allow.Accept("a"), qt.IsTrue)
		c.Assert(pc.Exec.Allow.Accept("d"), qt.IsFalse)
		c.Assert(pc.Exec.OsEnv.Accept("b"), qt.IsTrue)
		c.Assert(pc.Exec.OsEnv.Accept("e"), qt.IsFalse)
	})

	c.Run("Default exec.osEnv", func(c *qt.C) {
		c.Parallel()
		tomlConfig := `


someOtherValue = "bar"

[security]
[security.exec]
allow="a"

`

		cfg, err := config.FromConfigString(tomlConfig, "toml")
		c.Assert(err, qt.IsNil)

		pc, err := DecodeConfig(cfg)
		c.Assert(err, qt.IsNil)
		c.Assert(pc, qt.Not(qt.IsNil))
		c.Assert(pc.Exec.Allow.Accept("a"), qt.IsTrue)
		c.Assert(pc.Exec.OsEnv.Accept("PATH"), qt.IsTrue)
		c.Assert(pc.Exec.OsEnv.Accept("e"), qt.IsFalse)
	})

	c.Run("Enable inline shortcodes, legacy", func(c *qt.C) {
		c.Parallel()
		tomlConfig := `


someOtherValue = "bar"
enableInlineShortcodes=true

[security]
[security.exec]
allow="a"
osEnv="b"

`

		cfg, err := config.FromConfigString(tomlConfig, "toml")
		c.Assert(err, qt.IsNil)

		pc, err := DecodeConfig(cfg)
		c.Assert(err, qt.IsNil)
		c.Assert(pc.EnableInlineShortcodes, qt.IsTrue)
	})
}

func TestToTOML(t *testing.T) {
	c := qt.New(t)

	got := DefaultConfig.ToTOML()

	c.Assert(got, qt.Equals,
		"[security]\n  allowContent = ['! ^text/html$', '! ^text/org$']\n  enableInlineShortcodes = false\n\n  [security.exec]\n    allow = ['^(dart-)?sass(-embedded)?$', '^go$', '^git$', '^node$', '^postcss$']\n    osEnv = ['(?i)^((HTTPS?|NO)_PROXY|PATH(EXT)?|APPDATA|TE?MP|TERM|GO\\w+|(XDG_CONFIG_)?HOME|USERPROFILE|SSH_AUTH_SOCK|DISPLAY|LANG|SYSTEMDRIVE)$']\n\n  [security.funcs]\n    getenv = ['^HUGO_', '^CI$']\n\n  [security.http]\n    methods = ['(?i)GET|POST']\n    urls = ['(?i)^https?://[a-z0-9]', '! (?i)^https?://\\d+\\.', '! (?i)localhost', '! (?i)^https?://[^/?#]*@']\n\n  [security.node]\n    [security.node.permissions]\n      allowAddons = ['tailwindcss']\n      allowChildProcess = ['tailwindcss']\n      allowRead = ['.']\n      allowWorker = ['tailwindcss']\n      allowWrite = []\n      disable = false",
	)
}

func TestDecodeConfigDefault(t *testing.T) {
	t.Parallel()
	c := qt.New(t)

	pc, err := DecodeConfig(config.New())
	c.Assert(err, qt.IsNil)
	c.Assert(pc, qt.Not(qt.IsNil))
	c.Assert(pc.Exec.Allow.Accept("a"), qt.IsFalse)
	c.Assert(pc.Exec.Allow.Accept("node"), qt.IsTrue)
	c.Assert(pc.Exec.Allow.Accept("npx"), qt.IsFalse)

	c.Assert(pc.HTTP.URLs.Accept("https://example.org"), qt.IsTrue)
	c.Assert(pc.HTTP.Methods.Accept("POST"), qt.IsTrue)
	c.Assert(pc.HTTP.Methods.Accept("GET"), qt.IsTrue)
	c.Assert(pc.HTTP.Methods.Accept("get"), qt.IsTrue)
	c.Assert(pc.HTTP.Methods.Accept("DELETE"), qt.IsFalse)
	c.Assert(pc.HTTP.MediaTypes.Accept("application/msword"), qt.IsFalse)

	c.Assert(pc.Exec.OsEnv.Accept("PATH"), qt.IsTrue)
	c.Assert(pc.Exec.OsEnv.Accept("GOROOT"), qt.IsTrue)
	c.Assert(pc.Exec.OsEnv.Accept("HOME"), qt.IsTrue)
	c.Assert(pc.Exec.OsEnv.Accept("SSH_AUTH_SOCK"), qt.IsTrue)
	c.Assert(pc.Exec.OsEnv.Accept("a"), qt.IsFalse)
	c.Assert(pc.Exec.OsEnv.Accept("e"), qt.IsFalse)
	c.Assert(pc.Exec.OsEnv.Accept("MYSECRET"), qt.IsFalse)

	c.Assert(pc.Node.Permissions.IsEnabled(), qt.IsTrue)
	c.Assert(pc.Node.Permissions.AllowRead, qt.DeepEquals, []string{"."})
	c.Assert(pc.Node.Permissions.AllowWrite, qt.DeepEquals, []string{})
}

func TestCheckAllowedContent(t *testing.T) {
	t.Parallel()
	c := qt.New(t)

	c.Run("text/html denied by default", func(c *qt.C) {
		c.Parallel()
		pc, err := DecodeConfig(config.New())
		c.Assert(err, qt.IsNil)
		err = pc.CheckAllowedContent("text/html")
		c.Assert(err, qt.IsNotNil)
		c.Assert(err, qt.ErrorMatches, `(?s).*"text/html" is not whitelisted in policy "security\.allowContent".*`)
	})

	c.Run("text/org denied by default", func(c *qt.C) {
		c.Parallel()
		pc, err := DecodeConfig(config.New())
		c.Assert(err, qt.IsNil)
		err = pc.CheckAllowedContent("text/org")
		c.Assert(err, qt.IsNotNil)
		c.Assert(err, qt.ErrorMatches, `(?s).*"text/org" is not whitelisted in policy "security\.allowContent".*`)
	})

	c.Run("Other content types allowed by default", func(c *qt.C) {
		c.Parallel()
		pc, err := DecodeConfig(config.New())
		c.Assert(err, qt.IsNil)
		for _, mt := range []string{
			"text/markdown",
			"text/asciidoc",
			"text/rst",
			"text/pandoc",
		} {
			c.Assert(pc.CheckAllowedContent(mt), qt.IsNil, qt.Commentf(mt))
		}
	})

	c.Run("User can opt in to HTML", func(c *qt.C) {
		c.Parallel()
		tomlConfig := `
[security]
allowContent = ['.*']
`
		cfg, err := config.FromConfigString(tomlConfig, "toml")
		c.Assert(err, qt.IsNil)
		pc, err := DecodeConfig(cfg)
		c.Assert(err, qt.IsNil)
		c.Assert(pc.CheckAllowedContent("text/html"), qt.IsNil)
	})
}

func TestDecodeConfigNodePermissions(t *testing.T) {
	c := qt.New(t)

	c.Run("Custom paths", func(c *qt.C) {
		c.Parallel()
		tomlConfig := `
[security.node.permissions]
allowRead = ["/tmp", "."]
allowWrite = ["."]
`
		cfg, err := config.FromConfigString(tomlConfig, "toml")
		c.Assert(err, qt.IsNil)
		pc, err := DecodeConfig(cfg)
		c.Assert(err, qt.IsNil)
		c.Assert(pc.Node.Permissions.IsEnabled(), qt.IsTrue)
		c.Assert(pc.Node.Permissions.AllowRead, qt.DeepEquals, []string{"/tmp", "."})
		c.Assert(pc.Node.Permissions.AllowWrite, qt.DeepEquals, []string{"."})
	})

	c.Run("Disabled", func(c *qt.C) {
		c.Parallel()
		tomlConfig := `
[security.node.permissions]
disable = true
`
		cfg, err := config.FromConfigString(tomlConfig, "toml")
		c.Assert(err, qt.IsNil)
		pc, err := DecodeConfig(cfg)
		c.Assert(err, qt.IsNil)
		c.Assert(pc.Node.Permissions.IsEnabled(), qt.IsFalse)
	})

	c.Run("Wildcard", func(c *qt.C) {
		c.Parallel()
		tomlConfig := `
[security.node.permissions]
allowRead = ["*"]
allowWrite = ["*"]
`
		cfg, err := config.FromConfigString(tomlConfig, "toml")
		c.Assert(err, qt.IsNil)
		pc, err := DecodeConfig(cfg)
		c.Assert(err, qt.IsNil)
		c.Assert(pc.Node.Permissions.IsEnabled(), qt.IsTrue)
		c.Assert(pc.Node.Permissions.AllowRead, qt.DeepEquals, []string{"*"})
	})
}

func TestCheckAllowedHTTPAddress(t *testing.T) {
	t.Parallel()
	c := qt.New(t)
	pc := DefaultConfig

	for _, addr := range []string{
		"93.184.216.34:80",
		"[2606:4700::1]:443",
		"[64:ff9b::5db8:d822]:80",
	} {
		c.Assert(pc.CheckAllowedHTTPAddress("tcp", addr), qt.IsNil, qt.Commentf(addr))
	}

	for _, addr := range []string{
		"127.0.0.1:80",
		"[::1]:80",
		"10.0.0.1:8080",
		"172.16.0.1:80",
		"192.168.1.1:80",
		"169.254.169.254:80",
		"[fe80::1]:80",
		"[fc00::1]:80",
		"0.0.0.0:80",
		"[::ffff:127.0.0.1]:80",
		"100.64.0.1:80",
		"[::ffff:100.64.0.1]:80",
		"192.0.0.9:80",
		"192.0.2.1:80",
		"198.18.0.1:80",
		"198.51.100.1:80",
		"203.0.113.1:80",
		"240.0.0.1:80",
		"[2001:db8::1]:443",
		"[3fff::1]:443",
		"[64:ff9b::7f00:1]:80",
		"[64:ff9b::a9fe:a9fe]:80",
		"[64:ff9b:1::a00:1]:80",
	} {
		err := pc.CheckAllowedHTTPAddress("tcp", addr)
		c.Assert(err, qt.IsNotNil, qt.Commentf(addr))
		c.Assert(err, qt.ErrorMatches, `(?s).*is not whitelisted in policy "security\.http\.urls".*`, qt.Commentf(addr))
	}

	custom := DefaultConfig
	custom.HTTP.URLs = MustNewWhitelist(".*")
	c.Assert(custom.CheckAllowedHTTPAddress("tcp", "127.0.0.1:80"), qt.IsNil)
}
