package beacon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/drand/drand/v2/common"
	"github.com/drand/drand/v2/crypto"
	"github.com/drand/kyber"
	tlockhttp "github.com/drand/tlock/networks/http"
)

type Client struct {
	network     *tlockhttp.Network
	cache       *beaconCache
	urls        []string
	chainHash   string
	genesisTime int64
	period      time.Duration
}

type BeaconValue struct {
	Round      uint64
	Randomness []byte
	Signature  []byte
	Timestamp  time.Time
}
type ChainInfo struct {
	PublicKey   []byte
	Period      time.Duration
	GenesisTime int64
	Scheme      string
}

type drandChainInfo struct {
	PublicKey   string                 `json:"public_key"`
	Period      int64                  `json:"period"`
	GenesisTime int64                  `json:"genesis_time"`
	Hash        string                 `json:"hash"`
	GroupHash   string                 `json:"groupHash"`
	SchemeID    string                 `json:"schemeID"`
	Metadata    map[string]interface{} `json:"metadata"`
}
type beaconCache struct {
	mu      sync.RWMutex
	values  map[uint64]*BeaconValue
	maxSize int
}

func NewClient(urls []string, chainHash string) (*Client, error) {
	if len(urls) == 0 {
		return nil, fmt.Errorf("at least one drand URL is required")
	}
	network, err := tlockhttp.NewNetwork(urls[0], chainHash)
	if err != nil {
		return nil, fmt.Errorf("failed to create tlock network: %w", err)
	}
	chainInfo, err := fetchChainInfo(urls[0], chainHash)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch chain info: %w", err)
	}

	return &Client{
		network:     network,
		genesisTime: chainInfo.GenesisTime,
		period:      time.Duration(chainInfo.Period) * time.Second,
		cache: &beaconCache{
			values:  make(map[uint64]*BeaconValue),
			maxSize: 1000,
		},
		urls:      urls,
		chainHash: chainHash,
	}, nil
}
func fetchChainInfo(url, chainHash string) (*drandChainInfo, error) {
	infoURL := fmt.Sprintf("%s/%s/info", url, chainHash)

	resp, err := http.Get(infoURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch chain info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("chain info request failed with status %d", resp.StatusCode)
	}

	var info drandChainInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to decode chain info: %w", err)
	}

	return &info, nil
}

func (c *Client) GetBeacon(ctx context.Context, round uint64) (*BeaconValue, error) {
	if cached := c.cache.get(round); cached != nil {
		return cached, nil
	}

	signature, err := c.network.Signature(round)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch beacon round %d: %w", round, err)
	}

	if err := c.verifyBeacon(round, signature); err != nil {
		return nil, fmt.Errorf("beacon signature verification failed for round %d: %w", round, err)
	}

	timestamp := time.Unix(int64(uint64(c.genesisTime)+round*uint64(c.period.Seconds())), 0)

	beaconValue := &BeaconValue{
		Round:      round,
		Randomness: signature,
		Signature:  signature,
		Timestamp:  timestamp,
	}
	c.cache.set(round, beaconValue)

	return beaconValue, nil
}

func (c *Client) GetLatestBeacon(ctx context.Context) (*BeaconValue, error) {
	// Get current round number based on current time
	currentRound := c.network.RoundNumber(time.Now())

	return c.GetBeacon(ctx, currentRound)
}

func (c *Client) TimestampToRound(t time.Time) uint64 {
	return c.network.RoundNumber(t)
}

func (c *Client) RoundToTimestamp(round uint64) time.Time {
	timestamp := int64(uint64(c.genesisTime) + round*uint64(c.period.Seconds()))
	return time.Unix(timestamp, 0)
}

// verifyBeacon checks that a signature is a genuine drand threshold signature for
// the given round by verifying the BLS pairing equation e(sig, G2) == e(H(round), pubkey)
// against the chain's public key.
//
// Verifying here puts the check at the boundary where beacons enter the system,
// rather than relying on each consumer to do it. tlock.TimeUnlock verifies again
// before unwrapping a ciphertext, so the capsule path is covered either way, but
// GetBeacon also feeds the cache and the /api/beacon/signature endpoint, which
// hands signatures to callers with no tlock involved.
//
// The scheme returned by the network carries the correct hash-to-curve function and
// domain separation tag for the configured chain, so this stays correct across chains
// with different signature groups.
func (c *Client) verifyBeacon(round uint64, signature []byte) error {
	if len(signature) == 0 {
		return fmt.Errorf("empty signature")
	}

	scheme := c.network.Scheme()
	publicKey := c.network.PublicKey()

	beacon := &common.Beacon{
		Round:     round,
		Signature: common.HexBytes(signature),
	}

	if err := scheme.VerifyBeacon(beacon, publicKey); err != nil {
		return fmt.Errorf("BLS signature verification failed for round %d: %w", round, err)
	}

	return nil
}

// The methods below let *Client satisfy tlock.Network, so that tlock's hybrid
// encryption talks to this client rather than reaching for the network directly.
// The payoff is that every beacon tlock consumes has already been through
// verifyBeacon; the trust boundary stays in one place.

// ChainHash returns the configured drand chain hash.
func (c *Client) ChainHash() string {
	return c.chainHash
}

// Current returns the round number that corresponds to the given time.
func (c *Client) Current(t time.Time) uint64 {
	return c.network.RoundNumber(t)
}

// PublicKey returns the chain's group public key.
func (c *Client) PublicKey() kyber.Point {
	return c.network.PublicKey()
}

// Scheme returns the chain's cryptographic scheme.
func (c *Client) Scheme() crypto.Scheme {
	return c.network.Scheme()
}

// Signature returns the verified beacon signature for a round. tlock calls this
// when unwrapping a ciphertext, so decryption inherits the verification in
// GetBeacon rather than trusting whatever an endpoint returns.
func (c *Client) Signature(round uint64) ([]byte, error) {
	beaconValue, err := c.GetBeacon(context.Background(), round)
	if err != nil {
		return nil, err
	}
	return beaconValue.Signature, nil
}

// SwitchChainHash refuses to change chains at runtime. tlock offers this so a
// ciphertext can name its own chain, but honouring that would let a ciphertext
// redirect us to a chain we never configured, including a chained one that
// cannot carry a timelock guarantee.
func (c *Client) SwitchChainHash(hash string) error {
	if hash == c.chainHash {
		return nil
	}
	return fmt.Errorf("refusing to switch to chain %s: this server is pinned to %s", hash, c.chainHash)
}

func (c *Client) GetChainInfo() *ChainInfo {
	pubKeyPoint := c.network.PublicKey()
	pubKeyBytes, _ := pubKeyPoint.MarshalBinary()

	return &ChainInfo{
		PublicKey:   pubKeyBytes,
		Period:      c.period,
		GenesisTime: c.genesisTime,
		Scheme:      c.network.Scheme().Name,
	}
}
func (c *Client) WaitForRound(ctx context.Context, round uint64) (*BeaconValue, error) {
	currentTime := time.Now()
	roundTime := c.RoundToTimestamp(round)
	if currentTime.Before(roundTime) {
		waitDuration := roundTime.Sub(currentTime)
		select {
		case <-time.After(waitDuration):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	maxRetries := 10
	backoff := time.Second

	for i := 0; i < maxRetries; i++ {
		beacon, err := c.GetBeacon(ctx, round)
		if err == nil {
			return beacon, nil
		}
		select {
		case <-time.After(backoff):
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("failed to fetch round %d after %d retries", round, maxRetries)
}

func (bc *beaconCache) get(round uint64) *BeaconValue {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.values[round]
}

func (bc *beaconCache) set(round uint64, value *BeaconValue) {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	if _, exists := bc.values[round]; exists {
		bc.values[round] = value
		return
	}
	if len(bc.values) >= bc.maxSize {
		var oldestRound uint64 = round
		for r := range bc.values {
			if r < oldestRound {
				oldestRound = r
			}
		}
		if oldestRound < round {
			delete(bc.values, oldestRound)
		} else if len(bc.values) > 0 {
			for r := range bc.values {
				delete(bc.values, r)
				break
			}
		}
	}

	bc.values[round] = value
}

func (c *Client) Close() error {
	return nil
}
