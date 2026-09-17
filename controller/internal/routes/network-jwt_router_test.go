/*
	Copyright NetFoundry Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package routes

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_CachedJwt_SignsOnceUnderConcurrentCallers(t *testing.T) {
	req := require.New(t)

	route := NewNetworkJwtRouter()

	var calls atomic.Int32
	generate := func() (string, error) {
		calls.Add(1)
		return "signed-token", nil
	}

	const callers = 32

	results := make([]string, callers)
	wg := sync.WaitGroup{}
	wg.Add(callers)

	for i := 0; i < callers; i++ {
		go func(i int) {
			defer wg.Done()
			token, err := route.cachedJwt(generate)
			req.NoError(err)
			results[i] = token
		}(i)
	}

	wg.Wait()

	req.Equal(int32(1), calls.Load(), "the token is signed once and shared")

	for i, result := range results {
		req.Equal("signed-token", result, "caller %d got a different token", i)
	}
}

func Test_CachedJwt_FailureIsNotCached(t *testing.T) {
	req := require.New(t)

	route := NewNetworkJwtRouter()

	token, err := route.cachedJwt(func() (string, error) {
		return "", errors.New("signer unavailable")
	})

	req.Error(err)
	req.Empty(token)

	token, err = route.cachedJwt(func() (string, error) {
		return "signed-token", nil
	})

	req.NoError(err)
	req.Equal("signed-token", token)
}

func Test_CachedJwt_SecondCallUsesCache(t *testing.T) {
	req := require.New(t)

	route := NewNetworkJwtRouter()

	token, err := route.cachedJwt(func() (string, error) {
		return "first", nil
	})
	req.NoError(err)
	req.Equal("first", token)

	token, err = route.cachedJwt(func() (string, error) {
		return "second", nil
	})
	req.NoError(err)
	req.Equal("first", token)
}
