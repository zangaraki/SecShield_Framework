
package MyProject;



import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

public class LRUcache extends LinkedHashMap<HashMap<Integer, Integer>, Double>{
private final int capacity;

public LRUcache(int capacity) {
super(capacity, 0.75f, true);
this.capacity = capacity;
}

@Override
protected boolean removeEldestEntry(Map.Entry<HashMap<Integer, Integer>, Double> eldest) {
return size() > capacity;
}


@Override
public Double put(HashMap<Integer, Integer> key, Double value) {
return super.put(key, value);
}

@Override
public Double get(Object key) {
return super.get(key);
}
}
 
    

