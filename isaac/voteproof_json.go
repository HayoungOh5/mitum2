package isaac

import (
	"encoding/json"
	"time"

	"github.com/ProtoconNet/mitum2/base"
	"github.com/ProtoconNet/mitum2/util"
	"github.com/ProtoconNet/mitum2/util/encoder"
	"github.com/ProtoconNet/mitum2/util/hint"
	"github.com/ProtoconNet/mitum2/util/localtime"
	"github.com/ProtoconNet/mitum2/util/valuehash"
	"github.com/pkg/errors"
)

type baseVoteproofJSONMarshaler struct {
	FinishedAt   time.Time                     `json:"finished_at"`
	Majority     util.Hash                     `json:"majority"`
	ID           string                        `json:"id"`
	MajorityFact base.BallotFact               `json:"majority_fact,omitempty"`
	Signatures   []base.BaseNodeSign           `json:"signatures,omitempty"`
	SignFacts    []base.BallotSignFact         `json:"sign_facts"`
	Expels       []base.SuffrageExpelOperation `json:"expels,omitempty"`
	Point        base.StagePoint               `json:"point"`
	hint.BaseHinter
	Threshold base.Threshold `json:"threshold"`
}

func (vp baseVoteproof) jsonMarshaller() baseVoteproofJSONMarshaler {
	var majority util.Hash
	if vp.majority != nil {
		majority = vp.majority.Hash()
	}

	m := baseVoteproofJSONMarshaler{
		BaseHinter: vp.BaseHinter,
		FinishedAt: vp.finishedAt,
		Majority:   majority,
		Point:      vp.point,
		Threshold:  vp.threshold,
		ID:         vp.id,
	}

	if vp.majority != nil {
		m.MajorityFact = vp.majority
		signatures := make([]base.BaseNodeSign, 0, len(vp.sfs))
		for _, sf := range vp.sfs {
			ns := sf.NodeSigns()
			if len(ns) > 0 {
				switch t := ns[0].(type) {
				case base.BaseNodeSign:
					signatures = append(signatures, t)
				case *base.BaseNodeSign:
					if t != nil {
						signatures = append(signatures, *t)
					}
				}
			}
		}
		m.Signatures = signatures
	} else {
		m.SignFacts = vp.sfs
	}

	return m
}

func (vp baseVoteproof) MarshalJSON() ([]byte, error) {
	return util.MarshalJSON(vp.jsonMarshaller())
}

func (vp INITExpelVoteproof) MarshalJSON() ([]byte, error) {
	m := vp.jsonMarshaller()
	m.Expels = vp.expels

	return util.MarshalJSON(m)
}

func (vp INITStuckVoteproof) MarshalJSON() ([]byte, error) {
	m := vp.jsonMarshaller()
	m.Expels = vp.expels

	return util.MarshalJSON(m)
}

func (vp ACCEPTExpelVoteproof) MarshalJSON() ([]byte, error) {
	m := vp.jsonMarshaller()
	m.Expels = vp.expels

	return util.MarshalJSON(m)
}

func (vp ACCEPTStuckVoteproof) MarshalJSON() ([]byte, error) {
	m := vp.jsonMarshaller()
	m.Expels = vp.expels

	return util.MarshalJSON(m)
}

type baseVoteproofJSONUnmarshaler struct {
	FinishedAt   localtime.Time        `json:"finished_at"`
	ID           string                `json:"id"`
	Majority     valuehash.HashDecoder `json:"majority"`
	MajorityFact json.RawMessage       `json:"majority_fact"`
	Signatures   []json.RawMessage     `json:"signatures"`
	SignFacts    []json.RawMessage     `json:"sign_facts"`
	Expels       []json.RawMessage     `json:"expels"`
	Point        base.StagePoint       `json:"point"`
	Threshold    base.Threshold        `json:"threshold"`
}

func (vp *baseVoteproof) decodeJSON(b []byte, enc encoder.Encoder) (u baseVoteproofJSONUnmarshaler, _ error) {
	e := util.StringError("decode baseVoteproof")

	if err := enc.Unmarshal(b, &u); err != nil {
		return u, e.Wrap(err)
	}

	majority := u.Majority.Hash()

	if len(u.MajorityFact) > 0 && string(u.MajorityFact) != "null" {
		var commonFact base.BallotFact
		if err := encoder.Decode(enc, u.MajorityFact, &commonFact); err != nil {
			return u, e.Wrap(errors.WithMessage(err, "decode majority_fact"))
		}

		var isInit bool
		var initFact base.INITBallotFact
		var acceptFact base.ACCEPTBallotFact

		switch f := commonFact.(type) {
		case base.INITBallotFact:
			isInit = true
			initFact = f
		case base.ACCEPTBallotFact:
			isInit = false
			acceptFact = f
		default:
			return u, e.Wrap(errors.Errorf("unknown majority fact type: %T", commonFact))
		}

		vp.sfs = make([]base.BallotSignFact, len(u.Signatures))
		for i, rawSig := range u.Signatures {
			var ns base.BaseNodeSign
			if err := ns.DecodeJSON(rawSig, enc); err != nil {
				return u, e.Wrap(errors.WithMessagef(err, "decode signature at index %d", i))
			}

			if isInit {
				sf := NewINITBallotSignFact(initFact)
				sf.sign = ns
				vp.sfs[i] = sf
			} else {
				sf := NewACCEPTBallotSignFact(acceptFact)
				sf.sign = ns
				vp.sfs[i] = sf
			}
		}

		if majority != nil {
			if commonFact.Hash().Equal(majority) {
				vp.majority = commonFact
			}
		}

	} else if len(u.SignFacts) > 0 {
		vp.sfs = make([]base.BallotSignFact, len(u.SignFacts))

		for i := range u.SignFacts {
			if err := encoder.Decode(enc, u.SignFacts[i], &vp.sfs[i]); err != nil {
				return u, e.Wrap(err)
			}
			if majority != nil && vp.majority == nil {
				sfs := vp.sfs[i]
				if sfs.Fact().Hash().Equal(majority) {
					if fact, ok := sfs.Fact().(base.BallotFact); ok {
						vp.majority = fact
					}
				}
			}
		}
	}

	vp.threshold = u.Threshold
	vp.finishedAt = u.FinishedAt.Time
	vp.point = u.Point
	vp.id = u.ID

	return u, nil
}

func (vp *baseVoteproof) DecodeJSON(b []byte, enc encoder.Encoder) error {
	_, err := vp.decodeJSON(b, enc)

	return err
}

func decodeExpelVoteproofJSON(_ []byte, enc encoder.Encoder, u baseVoteproofJSONUnmarshaler, i interface{}) error {
	expels := make([]base.SuffrageExpelOperation, len(u.Expels))

	for i := range u.Expels {
		if err := encoder.Decode(enc, u.Expels[i], &expels[i]); err != nil {
			return err
		}
	}

	switch t := i.(type) {
	case *baseExpelVoteproof:
		t.expels = expels
	case *baseStuckVoteproof:
		t.expels = expels
	default:
		return errors.Errorf("expels not found, %T", t)
	}

	return nil
}

func (vp *baseExpelVoteproof) decodeJSON(
	b []byte, enc encoder.Encoder, u baseVoteproofJSONUnmarshaler,
) (err error) {
	return decodeExpelVoteproofJSON(b, enc, u, vp)
}

func (vp *baseStuckVoteproof) decodeJSON(b []byte, enc encoder.Encoder, u baseVoteproofJSONUnmarshaler) (err error) {
	return decodeExpelVoteproofJSON(b, enc, u, vp)
}

func (vp *INITExpelVoteproof) DecodeJSON(b []byte, enc encoder.Encoder) error {
	e := util.StringError("decode INITExpelVoteproof")

	u, err := vp.baseVoteproof.decodeJSON(b, enc)
	if err != nil {
		return e.Wrap(err)
	}

	if err := vp.baseExpelVoteproof.decodeJSON(b, enc, u); err != nil {
		return e.Wrap(err)
	}

	return nil
}

func (vp *INITStuckVoteproof) DecodeJSON(b []byte, enc encoder.Encoder) error {
	e := util.StringError("decode INITStuckVoteproof")

	u, err := vp.baseVoteproof.decodeJSON(b, enc)
	if err != nil {
		return e.Wrap(err)
	}

	if err := vp.baseStuckVoteproof.decodeJSON(b, enc, u); err != nil {
		return e.Wrap(err)
	}

	return nil
}

func (vp *ACCEPTExpelVoteproof) DecodeJSON(b []byte, enc encoder.Encoder) error {
	e := util.StringError("decode ACCEPTExpelVoteproof")

	u, err := vp.baseVoteproof.decodeJSON(b, enc)
	if err != nil {
		return e.Wrap(err)
	}

	if err := vp.baseExpelVoteproof.decodeJSON(b, enc, u); err != nil {
		return e.Wrap(err)
	}

	return nil
}

func (vp *ACCEPTStuckVoteproof) DecodeJSON(b []byte, enc encoder.Encoder) error {
	e := util.StringError("decode ACCEPTStuckVoteproof")

	u, err := vp.baseVoteproof.decodeJSON(b, enc)
	if err != nil {
		return e.Wrap(err)
	}

	if err := vp.baseStuckVoteproof.decodeJSON(b, enc, u); err != nil {
		return e.Wrap(err)
	}

	return nil
}
