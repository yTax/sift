# Plan 13 — A ranking that learns from your real/dud marks

## Why

The score weights (`sinks ×3`, `pairing ×3`, `history ×1.5`, …) are guesses. After you've read a few dozen repos, your marks say which signals actually led somewhere. This plan turns those marks into suggested weights. It's deliberately small: one classic statistical model, written in plain Go, with no AI service and no new dependency.

## What's already in place

The web UI has **Real lead** / **Dud** buttons. Marking a repo stores `Repo.Verdict`, `VerdictAt`, and `VerdictParts`: a copy of the score parts *as they were when you decided*. That snapshot matters, because later rescans and weight changes rewrite `Score.Parts` and would otherwise blur what you were looking at.

"Real" means "worth the time": the code had something worth digging into, whether or not it became a report. "Dud" means you read it and it was noise.

## How

1. **Training data:** every repo with a verdict. Features = its `VerdictParts` (each 0–10, scaled to 0–1). Label = 1 for real, 0 for dud.
2. **Model:** logistic regression, fit with plain gradient descent and L2 regularisation (about 60 lines of Go in `learn.go`). With this few examples and features, nothing fancier helps, and the result stays readable: one number per score part.
3. **When to fit:** only once there are at least **30 verdicts with at least 10 of each kind**. Below that, show "N more marks needed" instead of a guess.
4. **Turn coefficients into weights:** clamp negatives to 0 (a part that predicts duds shouldn't get a negative weight, just stop counting), then rescale so the largest weight matches today's largest (3). Weights stay positive numbers in the same range the settings already use.
5. **Check it's better, honestly:** leave-one-out over the marked repos. For each one, fit on the rest and check whether it ranks the held-out real leads above the held-out duds (AUC). Compare that with the current hand-set weights on the same data. Only suggest the learned weights if they beat the current ones.
6. **Suggest, don't apply.** The settings page shows current vs suggested weight per part, the two AUC numbers, and an **Apply** button. Applying writes the weights and rescores. You stay in control, and a few unlucky marks can't quietly wreck the ranking.

## Keep it honest
- The marks are biased toward what was already ranked high, because that's what you read. Say so on the page, and once in a while open something from the middle of the list and mark it too.
- Refit from scratch every time. Nothing is "trained" or stored except the verdicts themselves, so deleting a wrong mark fixes everything.

## Files
- `learn.go` — fit, leave-one-out evaluation, coefficients → weights.
- `server.go` — `GET /api/learn` (status, current vs suggested, AUCs), `POST /api/learn/apply`.
- `web/app.js` — the panel on the settings page.

## Done when
- With fewer than 30 marks (or under 10 of either kind) the page says how many more are needed and suggests nothing.
- A unit test with synthetic marks, where "real" depends only on `pairing`, produces a suggestion with `pairing` as the top weight and a better AUC than equal weights.
- Applying the suggestion rescores and the list order changes accordingly.
