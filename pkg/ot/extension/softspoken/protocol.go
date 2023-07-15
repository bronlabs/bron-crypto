package softspoken

// -------------------------------------------------------------------------- //
// ROUNDS (OTe):
//
//  0. Setup R & S:(...) ---(κ × BaseOT)---> (...)          [BaseOT]
//  1. R: (SessionId, x) ---(Round1)---> u                  [Ext.1, Ext.2, Ext.3]
//  2. S: (SessionId, u) ---(Round2)---> (χ)                [Ext.2, Ext.4, Check.1, T&R.1, T&R.3]
//  3. R:            (χ) ---(Round3)---> (x_val, t_val, z_A)[Check.2, T&R.1, T&R.2]
//  4. S: (x_val, t_val) ---(Round4)---> ()                 [Check.3]

// -------------------------------------------------------------------------- //
// ROUNDS (OTe with fiat-shamir):
//
//  0. Setup R & S:(...) ---(κ × BaseOT)---> (...)          [BaseOT]
//  1. R: (SessionId, x) ---(Round1)---> (u, x_val, t_val)  [Ext.1, Ext.2, Ext.3, Check.1, Check.2, T&R.1, T&R.2]
//  2. S: (SessionId, α) ---(Round2)---> (τ, z_B)        	[Ext.2, Ext.4, Check.1, T&R.1, T&R.3, Check.3]

// -------------------------------------------------------------------------- //
// ROUNDS (COTe):
//
//  0. Setup R & S:(...) ---(κ × BaseOT)---> (...)          [BaseOT]
//  1. R: (SessionId, x) ---(Round1)---> u                  [Ext.1, Ext.2, Ext.3]
//  2. S: (SessionId, α) ---(Round2)---> (χ, τ, z_B)        [Ext.2, Ext.4, Check.1, T&R.1, T&R.3, Derand.1]
//  3. R:         (χ, τ) ---(Round3)---> (x_val, t_val, z_A)[Check.2, T&R.1, T&R.2, Derand.2]
//  4. S: (x_val, t_val) ---(Round4)---> ()                 [Check.3]

// -------------------------------------------------------------------------- //
// ROUNDS (COTe with fiat-shamir):
//
//  0. Setup R & S:(...) ---(κ × BaseOT)---> (...)          [BaseOT]
//  1. R: (SessionId, x) ---(Round1)---> (u, x_val, t_val)  [Ext.1, Ext.2, Ext.3, Check.1, Check.2, T&R.1, T&R.2]
//  2. S: (SessionId, α) ---(Round2)---> (τ, z_B)        	[Ext.2, Ext.4, Check.1, T&R.1, T&R.3, Derand.1, Check.3]
//  3. R:            (τ) ---(Round3)---> (z_A)				[Derand.2]
