package com.sampacker.shibboleth.rba.context;

import org.opensaml.messaging.context.BaseContext;

public class RBAContext extends BaseContext
{
    private Double threatScore;
    private Integer modelVersion;

    public Double getThreatScore() { return threatScore; }
    public void setThreatScore(Double ts) { this.threatScore = ts; }

    public Integer getModelVersion() { return modelVersion; }
    public void setModelVersion(Integer modelVersion) { this.modelVersion = modelVersion; }
}