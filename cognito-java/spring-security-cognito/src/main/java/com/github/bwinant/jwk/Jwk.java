package com.github.bwinant.jwk;

/**
 * Simple JSON Web Key holder object
 */
public class Jwk
{
    private String alg;
    private String e;
    private String kid;
    private String kty;
    private String n;
    private String use;

    public String getAlg()
    {
        return alg;
    }

    public void setAlg(String alg)
    {
        this.alg = alg;
    }

    public String getE()
    {
        return e;
    }

    public void setE(String e)
    {
        this.e = e;
    }

    public String getKid()
    {
        return kid;
    }

    public void setKid(String kid)
    {
        this.kid = kid;
    }

    public String getKty()
    {
        return kty;
    }

    public void setKty(String kty)
    {
        this.kty = kty;
    }

    public String getN()
    {
        return n;
    }

    public void setN(String n)
    {
        this.n = n;
    }

    public String getUse()
    {
        return use;
    }

    public void setUse(String use)
    {
        this.use = use;
    }
}
