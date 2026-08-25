package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// A measurement rather than an assertion: how much of what a model returns is
// really in the email it was reading.
//
// It needs a live Ollama, so it is off unless OLLAMA_SCAN_LIVE names a server:
//
//	OLLAMA_SCAN_LIVE=127.0.0.1:11434 go test -run TestLiveModelsQuoteVerbatim -v .
//
// Skipped rather than mocked because a mock would answer the wrong question.
// The thing worth knowing is whether a particular model, on a particular
// machine, copies text out of a document or rewrites it -- and no fake can
// tell anybody that. The first real scan on this machine returned six findings
// and located none of them, which is what this exists to attribute: the model,
// not the search.
//
// What it has measured on 2026-08-15, against the fixture email:
//
//	asking for verbatim quotes
//	  deepseek-r1:7b    4 findings, 2 verbatim in 2.8s -- it quoted both
//	                    questions and then produced "answers" by restating
//	                    those same questions, missing the real one
//	  qwen3:8b          no answer within the 2m timeout
//
//	asking which numbered sentences
//	  deepseek-r1:7b    3 findings, 3 verbatim in 3.9s
//	  deepseek-r1:1.5b  2 findings, 2 verbatim in 1.5s
//	  deepseek-r1:8b    3 findings, 3 verbatim in 11.1s
//
// The first of those two blocks is why the second exists. The worked example
// in scanPrompt is what closed the last gap: without it deepseek-r1:7b found
// the question and missed the answer, which this test caught and named.
func TestLiveModelsQuoteVerbatim(t *testing.T) {
	host := os.Getenv("OLLAMA_SCAN_LIVE")
	if host == "" {
		t.Skip("set OLLAMA_SCAN_LIVE=host:port to measure a real server")
	}
	models := strings.Fields(os.Getenv("OLLAMA_SCAN_MODELS"))
	if len(models) == 0 {
		t.Skip("set OLLAMA_SCAN_MODELS to a space-separated list of models")
	}

	// The same email the splitter is tested against, so a failure here is
	// about the model rather than about the cutting.
	const body = splitFixture

	// Ground truth. Written out because "did it work" is otherwise a matter of
	// reading the log and forming an impression, and an impression does not
	// survive a change to the prompt.
	wantQuestions := []string{"Can you confirm the hinge is stainless"}
	wantAnswers := []string{"It does, with the one change"}
	// The failure that started this: the model turning a question it was asked
	// to find into an answer it wrote itself.
	forbidden := []string{"The hinge is stainless", "is stainless and not zinc plated."}

	for _, model := range models {
		t.Run(model, func(t *testing.T) {
			a := prefsApp(t)
			ctx := context.Background()
			if err := a.settings.Set(ctx, "ollama.host", host); err != nil {
				t.Fatal(err)
			}
			if err := a.SetApprovedModels(ctx, []string{model}); err != nil {
				t.Fatal(err)
			}
			if err := a.prefs2.Set(ctx, "sam@example.com", "ollama.model", model); err != nil {
				t.Fatal(err)
			}

			start := time.Now()
			found, err := a.ExtractQA(ctx, a.prefsFor("sam@example.com"), body)
			took := time.Since(start)
			if err != nil {
				t.Fatalf("%s: %v", model, err)
			}

			var verbatim int
			for _, f := range found {
				mark := "PARAPHRASE"
				if f.Verbatim {
					verbatim++
					mark = "verbatim"
				}
				t.Logf("  %-8s %-10s @%-5d %s", f.Kind, mark, f.Offset, oneLine(f.Text))
			}
			t.Logf("%s: %d findings, %d verbatim, %s", model, len(found), verbatim, took.Round(time.Millisecond))

			// Every finding must be a substring of the message it came from,
			// at the offset it reports. This is the promise the numbered list
			// exists to keep, and it is checked against a live model because
			// that is the only place it can be broken.
			for _, f := range found {
				if !f.Verbatim {
					t.Errorf("%s returned something that is not in the email: %q",
						model, oneLine(f.Text))
					continue
				}
				if f.Offset < 0 || f.Offset+len(f.Text) > len(body) ||
					body[f.Offset:f.Offset+len(f.Text)] != f.Text {
					t.Errorf("%s: the offset does not point at the text: %+v", model, f)
				}
			}
			for _, bad := range forbidden {
				for _, f := range found {
					if strings.Contains(oneLine(f.Text), bad) && f.Kind == "answer" {
						t.Errorf("%s answered the question itself: %q", model, oneLine(f.Text))
					}
				}
			}

			// And it has to actually find what is there. A model that returns
			// nothing is safe and useless.
			if !anyContains(found, "question", wantQuestions) {
				t.Errorf("%s missed the question in the email", model)
			}
			if !anyContains(found, "answer", wantAnswers) {
				t.Errorf("%s missed the answer in the email", model)
			}
		})
	}
}

// anyContains reports whether some finding of this kind holds one of these.
func anyContains(found []Finding, kind string, wants []string) bool {
	for _, f := range found {
		if f.Kind != kind {
			continue
		}
		for _, w := range wants {
			if strings.Contains(oneLine(f.Text), w) {
				return true
			}
		}
	}
	return false
}

// oneLine keeps a multi-line quote on one line of test output.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
