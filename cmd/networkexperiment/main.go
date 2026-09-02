// networkexperiment is a fixed-seed multi-node event emulator for the
// partially synchronous mother-tree games used in the TGPoW security proof.
// It reports targeted persistence attacks and honest finalized-chain growth
// under bounded propagation delay. It is not a replacement for a deployment
// across independent physical hosts.
package main

import (
	"flag"
	"fmt"
	"math/rand"
	"sort"
)

type block struct {
	id      int
	parent  int
	height  int
	attack  bool
	honest  bool
	created int
}

type node struct {
	tip   int
	known map[int]bool
}

type delivery struct {
	at      int
	node    int
	blockID int
}

type treeSim struct {
	rng        *rand.Rand
	blocks     []block
	nodes      []node
	deliveries []delivery
	delta      int
	attackTie  bool
}

func main() {
	nodeCount := flag.Int("nodes", 16, "number of honest nodes")
	persistenceTrials := flag.Int("persistence-trials", 20000, "trials per persistence parameter set")
	growthRuns := flag.Int("growth-runs", 100, "runs per growth parameter set")
	growthSlots := flag.Int("growth-slots", 5000, "slots per growth run")
	blockProbability := flag.Float64("block-probability", 0.20, "probability that a slot has a block opportunity")
	flag.Parse()
	if *nodeCount < 2 || *persistenceTrials <= 0 || *growthRuns <= 0 || *growthSlots <= 0 || *blockProbability <= 0 || *blockProbability > 1 {
		panic("invalid experiment parameters")
	}

	fmt.Printf("CONFIG nodes=%d persistenceTrials=%d growthRuns=%d growthSlots=%d blockProbability=%.3f seed=20260828\n",
		*nodeCount, *persistenceTrials, *growthRuns, *growthSlots, *blockProbability)
	for _, alpha := range []float64{0.30, 0.40} {
		for _, depth := range []int{4, 8} {
			for _, delta := range []int{0, 2, 5} {
				wins := 0
				for trial := 0; trial < *persistenceTrials; trial++ {
					seed := int64(20260828 + int(alpha*100)*1000000 + depth*10000 + delta*100 + trial)
					if persistenceTrial(*nodeCount, alpha, depth, delta, seed) {
						wins++
					}
				}
				fmt.Printf("PERSISTENCE alpha=%.2f depth=%d delta=%d trials=%d violations=%d probability=%.6f\n",
					alpha, depth, delta, *persistenceTrials, wins, float64(wins)/float64(*persistenceTrials))
			}
		}
	}
	for _, alpha := range []float64{0.30, 0.40} {
		for _, delta := range []int{0, 2, 5} {
			growthRates := make([]float64, 0, *growthRuns)
			maxGaps := make([]int, 0, *growthRuns)
			forkRates := make([]float64, 0, *growthRuns)
			for run := 0; run < *growthRuns; run++ {
				seed := int64(30260828 + int(alpha*100)*1000000 + delta*10000 + run)
				growth, maxGap, forkRate := growthTrial(*nodeCount, alpha, delta, *growthSlots, *blockProbability, seed)
				growthRates = append(growthRates, growth)
				maxGaps = append(maxGaps, maxGap)
				forkRates = append(forkRates, forkRate)
			}
			sort.Ints(maxGaps)
			fmt.Printf("GROWTH alpha=%.2f delta=%d runs=%d slots=%d finalizedPer1000=%.3f maxNoGrowthP95=%d staleRate=%.6f\n",
				alpha, delta, *growthRuns, *growthSlots, mean(growthRates), maxGaps[int(float64(len(maxGaps)-1)*0.95)], mean(forkRates))
		}
	}
}

func newTreeSim(nodes, delta int, rng *rand.Rand, attackTie bool) *treeSim {
	sim := &treeSim{rng: rng, delta: delta, attackTie: attackTie}
	sim.blocks = append(sim.blocks, block{id: 0, parent: -1, height: 0})
	for i := 0; i < nodes; i++ {
		sim.nodes = append(sim.nodes, node{tip: 0, known: map[int]bool{0: true}})
	}
	return sim
}

func persistenceTrial(nodeCount int, alpha float64, depth, delta int, seed int64) bool {
	sim := newTreeSim(nodeCount, delta, rand.New(rand.NewSource(seed)), true)
	honestTip := 0
	for height := 1; height <= depth; height++ {
		honestTip = sim.addBlock(honestTip, true, false, -height)
		for i := range sim.nodes {
			sim.learn(i, honestTip)
		}
	}
	attackTip := 0
	published := false
	for step := 0; step < 20000; step++ {
		sim.process(step)
		if sim.rng.Float64() < alpha {
			attackTip = sim.addBlock(attackTip, false, true, step)
		} else {
			producer := sim.rng.Intn(nodeCount)
			newBlock := sim.addBlock(sim.nodes[producer].tip, true, false, step)
			sim.learn(producer, newBlock)
			sim.broadcast(step, producer, newBlock)
		}
		sim.process(step)
		if !published && sim.blocks[attackTip].height >= sim.minTipHeight() {
			path := sim.pathFromGenesis(attackTip)
			for _, blockID := range path[1:] {
				for i := range sim.nodes {
					sim.learn(i, blockID)
				}
			}
			published = true
			for _, n := range sim.nodes {
				if sim.blocks[n.tip].attack {
					return true
				}
			}
		}
		if sim.minTipHeight()-sim.blocks[attackTip].height >= 32 {
			return false
		}
	}
	return false
}

func growthTrial(nodeCount int, alpha float64, delta, slots int, blockProbability float64, seed int64) (float64, int, float64) {
	sim := newTreeSim(nodeCount, delta, rand.New(rand.NewSource(seed)), false)
	const confirmationDepth = 6
	lastFinalized, lastGrowthSlot, maxGap := 0, 0, 0
	honestBlocks := 0
	for slot := 0; slot < slots; slot++ {
		sim.process(slot)
		if sim.rng.Float64() < blockProbability && sim.rng.Float64() >= alpha {
			producer := sim.rng.Intn(nodeCount)
			newBlock := sim.addBlock(sim.nodes[producer].tip, true, false, slot)
			honestBlocks++
			sim.learn(producer, newBlock)
			sim.broadcast(slot, producer, newBlock)
		}
		sim.process(slot)
		finalized := sim.commonPrefixHeight() - confirmationDepth
		if finalized < 0 {
			finalized = 0
		}
		if finalized > lastFinalized {
			if gap := slot - lastGrowthSlot; gap > maxGap {
				maxGap = gap
			}
			lastGrowthSlot = slot
			lastFinalized = finalized
		}
	}
	for slot := slots; slot <= slots+delta+2; slot++ {
		sim.process(slot)
	}
	commonHeight := sim.commonPrefixHeight()
	finalized := commonHeight - confirmationDepth
	if finalized < 0 {
		finalized = 0
	}
	if gap := slots - lastGrowthSlot; gap > maxGap {
		maxGap = gap
	}
	staleRate := 0.0
	if honestBlocks > 0 {
		staleRate = float64(honestBlocks-commonHeight) / float64(honestBlocks)
	}
	return float64(finalized) / float64(slots) * 1000, maxGap, staleRate
}

func (s *treeSim) addBlock(parent int, honest, attack bool, created int) int {
	id := len(s.blocks)
	s.blocks = append(s.blocks, block{id: id, parent: parent, height: s.blocks[parent].height + 1, honest: honest, attack: attack, created: created})
	return id
}

func (s *treeSim) broadcast(slot, producer, blockID int) {
	for i := range s.nodes {
		if i == producer {
			continue
		}
		delay := 0
		if s.delta > 0 {
			delay = s.rng.Intn(s.delta + 1)
		}
		s.deliveries = append(s.deliveries, delivery{at: slot + delay, node: i, blockID: blockID})
	}
}

func (s *treeSim) process(slot int) {
	remaining := s.deliveries[:0]
	for _, item := range s.deliveries {
		if item.at > slot {
			remaining = append(remaining, item)
			continue
		}
		parent := s.blocks[item.blockID].parent
		if parent >= 0 && !s.nodes[item.node].known[parent] {
			item.at = slot + 1
			remaining = append(remaining, item)
			continue
		}
		s.learn(item.node, item.blockID)
	}
	s.deliveries = remaining
}

func (s *treeSim) learn(nodeID, blockID int) {
	n := &s.nodes[nodeID]
	n.known[blockID] = true
	current := s.blocks[n.tip]
	candidate := s.blocks[blockID]
	if candidate.height > current.height || (candidate.height == current.height && s.prefer(candidate, current)) {
		n.tip = blockID
	}
}

func (s *treeSim) prefer(candidate, current block) bool {
	if s.attackTie && candidate.attack != current.attack {
		return candidate.attack
	}
	return candidate.id < current.id
}

func (s *treeSim) minTipHeight() int {
	minimum := s.blocks[s.nodes[0].tip].height
	for _, n := range s.nodes[1:] {
		if height := s.blocks[n.tip].height; height < minimum {
			minimum = height
		}
	}
	return minimum
}

func (s *treeSim) pathFromGenesis(tip int) []int {
	path := make([]int, s.blocks[tip].height+1)
	for tip >= 0 {
		path[s.blocks[tip].height] = tip
		tip = s.blocks[tip].parent
	}
	return path
}

func (s *treeSim) commonPrefixHeight() int {
	ancestor := s.nodes[0].tip
	for _, n := range s.nodes[1:] {
		ancestor = s.lowestCommonAncestor(ancestor, n.tip)
	}
	return s.blocks[ancestor].height
}

func (s *treeSim) lowestCommonAncestor(left, right int) int {
	for s.blocks[left].height > s.blocks[right].height {
		left = s.blocks[left].parent
	}
	for s.blocks[right].height > s.blocks[left].height {
		right = s.blocks[right].parent
	}
	for left != right {
		left = s.blocks[left].parent
		right = s.blocks[right].parent
	}
	return left
}

func mean(values []float64) float64 {
	total := 0.0
	for _, value := range values {
		total += value
	}
	return total / float64(len(values))
}
