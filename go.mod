module vaultdb

go 1.12

require (
	github.com/go-stack/stack v1.8.0 // indirect
	github.com/hashicorp/vault v1.4.1
	github.com/hashicorp/vault/api v1.0.5-0.20200317185738-82f498082f02
	github.com/hashicorp/vault/sdk v0.1.14-0.20200429182704-29fce8f27ce4
	github.com/lib/pq v1.5.2
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.4.0
	github.com/tevino/abool v0.0.0-20170917061928-9b9efcf221b5
	go.uber.org/zap v1.15.0
)

replace github.com/hashicorp/vault/sdk v0.1.14-0.20191229212425-c478d00be0d6 => github.com/hashicorp/vault/sdk v0.1.14-0.20200121232954-73f411823aa0
