package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"
)

type report struct {
	w      io.Writer
	styled bool
}

func (r report) bold(text string) string {
	if r.styled {
		return "\x1b[1m" + text + "\x1b[0m"
	}
	return text
}

func (r report) section(title string) {
	fmt.Fprintln(r.w, "\n"+r.bold(title))
}

func (r report) table(headers []string, rows [][]string) {
	widths := make([]int, len(headers))
	for i, header := range headers {
		widths[i] = utf8.RuneCountInString(header)
		for _, row := range rows {
			widths[i] = max(widths[i], utf8.RuneCountInString(row[i]))
		}
	}
	border := func(left, middle, right string) {
		fmt.Fprint(r.w, left)
		for i, width := range widths {
			if i > 0 {
				fmt.Fprint(r.w, middle)
			}
			fmt.Fprint(r.w, strings.Repeat("─", width+2))
		}
		fmt.Fprintln(r.w, right)
	}
	row := func(cells []string, header bool) {
		fmt.Fprint(r.w, "│")
		for i, cell := range cells {
			padding := strings.Repeat(" ", widths[i]-utf8.RuneCountInString(cell))
			if i == 0 {
				cell += padding
			} else {
				cell = padding + cell
			}
			if header {
				cell = r.bold(cell)
			}
			fmt.Fprint(r.w, " "+cell+" │")
		}
		fmt.Fprintln(r.w)
	}
	border("┌", "┬", "┐")
	row(headers, true)
	border("├", "┼", "┤")
	for _, cells := range rows {
		row(cells, false)
	}
	border("└", "┴", "┘")
}

func percent(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return 100 * float64(n) / float64(total)
}

func number(n int) string {
	text := strconv.Itoa(n)
	for i := len(text) - 3; i > 0; i -= 3 {
		text = text[:i] + "," + text[i:]
	}
	return text
}

func (s results) print(w io.Writer, entries inventory, verbose bool) {
	r := report{w: w}
	if file, ok := w.(*os.File); ok {
		info, err := file.Stat()
		r.styled = err == nil && info.Mode()&os.ModeCharDevice != 0 && os.Getenv("TERM") != "dumb" && os.Getenv("NO_COLOR") == ""
	}
	fmt.Fprintln(w, r.bold(fmt.Sprintf("Dofus key finder · %s IDs · %s versions", number(s.uniqueIDs), number(s.total))))
	fmt.Fprintf(w, "%s plaintext · %s encrypted · %s invalid\n", number(s.plaintext), number(s.encrypted), number(s.invalid))

	fmt.Fprintln(w)
	var coverage [][]string
	for _, row := range []struct {
		label string
		count int
	}{
		{"Exact key", s.exactCovered},
		{"Imported key only", s.importedOnly},
		{"Prediction only", s.predictedOnly},
		{"No key or prediction", s.missing},
	} {
		coverage = append(coverage, []string{row.label, number(row.count), fmt.Sprintf("%.2f%%", percent(row.count, s.encrypted))})
	}
	r.table([]string{"Encrypted maps", "Versions", "Share"}, coverage)
	fmt.Fprintf(w, "Known keys   %s (+%s versions)\n", r.bold(fmt.Sprintf("%s/%s (%.2f%%)", number(s.afterCoverage), number(s.encrypted), percent(s.afterCoverage, s.encrypted))), number(s.afterCoverage-s.beforeCoverage))
	fmt.Fprintf(w, "Exact        +%s added · %s promoted · %s corrected\n", number(s.added), number(s.promoted), number(s.corrected))
	fmt.Fprintf(w, "Predictions  %s new · %s changed · %s unchanged · %s preserved\n", number(s.newPredictions), number(s.changedPredictions), number(s.unchangedPredictions), number(s.preserved))
	var issues []string
	for _, issue := range []struct {
		count int
		label string
	}{
		{s.invalid, "invalid maps"},
		{s.failed, "solver failures"},
		{s.predictionErrors, "prediction errors"},
		{s.conflicts, "key conflicts"},
		{s.skippedTraining, "training skips"},
		{s.noTraining, "predictions skipped without training"},
	} {
		if issue.count > 0 {
			issues = append(issues, number(issue.count)+" "+issue.label)
		}
	}
	if len(issues) == 0 {
		issues = append(issues, "none")
	}
	fmt.Fprintln(w, "Issues       "+strings.Join(issues, " · "))
	if !verbose {
		return
	}

	r.section("Recovery")
	fmt.Fprintf(w, "With plaintext maps  %s/%s (%.2f%%)\n", number(s.plaintext+s.afterCoverage), number(s.total), percent(s.plaintext+s.afterCoverage, s.total))
	fmt.Fprintf(w, "Known key coverage   %.2f%% → %.2f%%\n", percent(s.beforeCoverage, s.encrypted), percent(s.afterCoverage, s.encrypted))
	fmt.Fprintf(w, "Deterministic        %s exact · %s ambiguous · %s failed\n", number(s.recovered), number(s.ambiguous), number(s.failed))
	fmt.Fprintf(w, "Existing keys        %s confirmed · %s conflicts\n", number(s.confirmed), number(s.conflicts))
	fmt.Fprintf(w, "Training maps        %s used · %s skipped\n", number(s.trained), number(s.skippedTraining))
	fmt.Fprintf(w, "Key bytes            %s determined · %s ambiguous\n", number(s.determinedBytes), number(s.ambiguousBytes))
	if s.noTraining > 0 {
		fmt.Fprintf(w, "Prediction skipped   %s without training data\n", number(s.noTraining))
	}

	r.section("Ambiguous maps without imported/exact keys")
	r.table([]string{"Ambiguous key bytes", "1", "2–4", "5–16", "17+"}, [][]string{
		{"Map versions", number(s.unknownAmbiguity[0]), number(s.unknownAmbiguity[1]), number(s.unknownAmbiguity[2]), number(s.unknownAmbiguity[3])},
	})

	if s.invalid+s.failed+s.predictionErrors == 0 {
		r.section("Failures: none")
	} else {
		r.section("Failures")
		r.table([]string{"Reason", "Count"}, [][]string{
			{"Invalid map data", number(s.invalid)},
			{"No plausible length", number(s.noKeyLength)},
			{"Other solver errors", number(s.solverErrors)},
			{"Prediction errors", number(s.predictionErrors)},
		})
	}

	r.section("Inventory files (all versions)")
	fmt.Fprintf(w, "%s imported / %s exact / %s predicted\n", number(len(entries.imported)), number(len(entries.exact)), number(len(entries.predicted)))
	fmt.Fprintln(w, "\nImported keys are unverified; predictions are excluded from coverage.")
	fmt.Fprintln(w, "Exact means unique under the solver's constraints.")
}
