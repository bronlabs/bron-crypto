// Package hierarchical implements hierarchical conjunctive threshold access
// structures.
//
// In a hierarchical access structure shareholders are partitioned into ordered
// levels, each with a strictly increasing cumulative threshold. A coalition is
// qualified if, at every level, the cumulative number of members from that
// level and all preceding levels meets the level's threshold.
//
// This access structure is used by the Tassa hierarchical secret sharing
// scheme. MSP induction and maximal unqualified set enumeration are not yet
// implemented.
package hierarchical
