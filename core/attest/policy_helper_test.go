package attest

// PolicyAuthorizeDigest is the policy digest of a key that is usable
// exactly when keyName has approved a policy for policyRef. The slot's
// policy begins with it (SlotPolicyDigest).
func PolicyAuthorizeDigest(keyName, policyRef []byte) []byte {
	return PolicyDigest(policyAuthorize(keyName, policyRef))
}
