from __future__ import annotations

HIGH_SIGNAL={"aws_access_key","github_token","gitlab_token","slack_token","stripe_secret_key","sendgrid_api_key","private_key"}

def score_cluster(*, observations:int, repositories:int, authors:int, confidence:float,
                  secret_type:str, historical:bool=True) -> tuple[float,str]:
    score=confidence*55
    score+=min(observations,12)*2.5
    score+=min(repositories,6)*5
    score+=min(authors,6)*2
    if secret_type in HIGH_SIGNAL: score+=18
    if historical: score+=5
    score=min(100.0,score)
    label="critical" if score>=85 else "high" if score>=65 else "medium" if score>=40 else "low"
    return round(score,1),label
