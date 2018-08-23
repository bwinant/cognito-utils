package com.github.bwinant.jwk;

import java.security.PublicKey;
import java.util.Set;

public interface JwkStore
{
    Set<String> getKeyIds();

    PublicKey getKey(String keyId);
}
