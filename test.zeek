event http_reply(c: connection, version: string, code: count, reason: string){
    SumStats::observe("count of response",
                    SumStats::Key($host=c$id$orig_h),
                    SumStats::Observation($num=1));
    if(code == 404){
        SumStats::observe("count of 404 response",
                        SumStats::Key($host=c$id$orig_h),
                        SumStats::Observation($num=1));
        SumStats::observe("count of unique 404 response",
                        SumStats::Key($host=c$id$orig_h),
                        SumStats::Observation($str=c$http$uri));
    }
}
    
event zeek_init(){
    local ruducer1 = SumStats::Reducer($stream="count of response",
                                        $apply=set(SumStats::SUM));
    local reducer2 = SumStats::Reducer($stream="count of 404 response",
                                        $apply=set(SumStats::SUM));
    local reducer3 = SumStats::Reducer($stream="count of unique 404 response",
                                        $apply=set(SumStats::UNIQUE));
    
    SumStats::create([$name = "Detect scanner",
                        $epoch = 10min,
                        $reducers = set(ruducer1,reducer2,reducer3),
                        $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = {
                            local radio404 : double = result["count of 404 response"]$sum / result["count of response"]$sum;
                            local uniradio404 : double = result["count of unique 404 response"]$unique / result["count of 404 response"]$sum;
                            if(result["count of 404 response"]$sum > 2 && radio404 > 0.2 && uniradio404 > 0.5){
                                print fmt("%s is a scanner with %.0f scan attemps on %s urls", key$host, result["count of 404 response"]$sum, result["count of unique 404 response"]$unique);
                            }
                        }]);
}