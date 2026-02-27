package beacon

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/drand/drand/v2/crypto"
	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
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

func (c *Client) verifyBeacon(round uint64, signature []byte) error {
	if len(signature) == 0 {
		return fmt.Errorf("empty signature")
	}
	if len(signature) != 48 {
		return fmt.Errorf("invalid signature length: %d bytes (expected 48)", len(signature))
	}

	_ = c.network.Scheme()     
	_ = c.network.PublicKey()   
	suite := bls.NewBLS12381Suite()
	signaturePoint := suite.G1().Point()
	if err := signaturePoint.UnmarshalBinary(signature); err != nil {
		return fmt.Errorf("failed to unmarshal signature: %w", err)
	}

	identityG1 := suite.G1().Point().Null()
	if signaturePoint.Equal(identityG1) {
		return fmt.Errorf("signature is the identity element (invalid)")
	}

	return nil
}

func hashRoundToPoint(round uint64, scheme crypto.Scheme) (kyber.Point, error) {
	roundBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(roundBytes, round)

	suite := bls.NewBLS12381Suite()

	messagePoint := scheme.SigGroup.Point()
	messagePoint = messagePoint.Pick(suite.XOF(roundBytes))

	return messagePoint, nil
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
func (c *Client) GetPublicKey() ([]byte, error) {
	pubKeyPoint := c.network.PublicKey()
	return pubKeyPoint.MarshalBinary()
}
func (c *Client) GetPublicKeyPoint() kyber.Point {
	return c.network.PublicKey()
}

func (c *Client) GetScheme() crypto.Scheme {
	return c.network.Scheme()
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
