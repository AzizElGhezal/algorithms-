#PatternCount

def PatternCount(Text, Pattern):
    count = 0
    for i in range(len(Text)-len(Pattern)+1):
        if Text[i:i+len(Pattern)] == Pattern:
            count = count+1
    return count 

Text ="GATCCAGATCCCCATAC"
Pattern = "ATA"

print(PatternCount(Text, Pattern))

#FrequencyMap

def FrequentWords(Text, k):
    words = []
    freq = FrequencyMap(Text, k)
    m = max(freq.values())
    for key, value in freq.items():
        if value == m:
         words.append(key)
    return words   

def FrequencyMap(Text, k):
    freq = {}
    n = len(Text)
    for i in range(n-k+1):
        Pattern = Text[i:i+k]
        freq[Pattern] = 0
    for i in range(n-k+1):
        Pattern = Text[i:i+k]
        freq[Pattern] += 1
    return freq

Text = "atcaatgattatttcatatttcatattt"
k = 9

print(FrequentWords(Text, k))
