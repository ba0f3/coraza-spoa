package autoban

// The Lua algorithms and their reply parsers are implemented in Task 4. These
// minimal parsers keep the transport's Store methods compilable until then.

func parseBeginResult(_ interface{}) (BeginResult, error) {
	return BeginResult{}, nil
}

func parseObserveResult(_ interface{}) (ObserveResult, error) {
	return ObserveResult{}, nil
}

func parseUnbanResult(_ interface{}) (UnbanResult, error) {
	return UnbanResult{}, nil
}

func parseInspectResult(_ interface{}) (InspectResult, error) {
	return InspectResult{}, nil
}

func parseListResult(_ interface{}) (ListResult, error) {
	return ListResult{}, nil
}
