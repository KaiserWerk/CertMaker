package entity

type HTTP01ChallengeRequest struct {
	ChallengePort uint16 `json:"challenge_port"`
}
