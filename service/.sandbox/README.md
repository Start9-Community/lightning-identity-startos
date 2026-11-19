Sandbox-only module file. The development sandbox can reach GitHub but not
proxy.golang.org, gopkg.in, golang.org or gitlab, so this modfile replaces
every non-GitHub module with its GitHub mirror (or an empty stub for modules
that are in the graph but never imported). Build with:

    cd service && go build -modfile=.sandbox/go.mod ./...

Never ship this file; the real go.mod/go.sum are the ones at service/.
