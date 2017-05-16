import scala.collection.mutable.Map

val l = scala.io.Source.fromFile(args(0)).getLines.toList
//l.distinct.map(x=>(x, l.count(_==x))).sortBy(x=>(-x._2)).foreach(x=>println(x._1+" "+x._2))

def freq(l: List[String]): Map[String,Int] = {
	val ans = scala.collection.mutable.Map.empty[String, Int]
	for(item <- l){
		val count = ans.getOrElse(item,0)
		ans+=(item -> (count+1))
	}
	ans
}
freq(l).toList.sortBy(x=>(-x._2)).foreach(x=>println(x._1+" "+x._2))

