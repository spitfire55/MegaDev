//this program takes in a listing of domain names to frequencies and parses them

class DomainTrie { 
  
  def isEmpty: Boolean = (root.isEmpty && !root.canEndHere)

  def apply(str: String): Boolean = { // is the string in the set?
    root.search(str.split(".").toList.reverse)
  }

  def +=(tup: (String,String)) { // add a new string to the set
    val listOStr: List[String] = tup._1.split('.').toList.reverse
    val freq: Int  = Integer.parseInt(tup._2)
    //println(tup,tup._1,tup._1.split('.').toList,listOStr)
    root = root.add(listOStr, freq)
    //println(root)  
}
  
 def stats(levels: Int): Unit = root.printStats(levels) 
 def findCSNonceDomains(lenSubDomain: Int, thr: Double): Unit = root.findCSNonceDomains(lenSubDomain, thr)
	

 
 
  abstract class T{
 	var canEndHere: Boolean 
  	def isEmpty: Boolean 
	def search(list: List[String]): Boolean
  	def add(list: List[String], inFreq: Int): T 
	def getFreq: Int	
  	def getNumSubDomains: Int
	def mkList: List[String] = {
	   def h(node: T): List[String] = {
		node match {
			case t: TrieNode => {
				var ans = List.empty[String]
				for((parentStr,kid)<-t.children){
					val subAns = h(kid)
					if(!subAns.isEmpty) ans=subAns.map(parentStr+"."+_)++ans
				}
				if (t.canEndHere) "" +: ans else ans 
			}
			case _	=> if (node.canEndHere) List("") else List.empty[String] 

		}
	   }
	   h(this)	
  	}
	

	def printStats(level: Int): Unit ={
		def h(level: Int, node: T,start: String = "|___"): (String,Int) ={
			node match {
                       	case t: TrieNode => {
                        	val sb = new StringBuilder
				var count = 0
				if(level == 0) return ("",t.getNumSubDomains)
				//(start+t.getNumSubDomains.toString, t.getNumSubDomains)      	
				for((pStr,kid)<-t.children){//TODO Order
                                        //sb.append(start+pStr+"\n")
					val (kidStr, kidNum) = h(level-1,kid,'\t'+start)
                                   	count+=kidNum    	
					sb.append(start+pStr+" count: "+kidNum+"\n")
					if(!kidStr.isEmpty)sb.append(kidStr+"\n")
				    }
					(sb.toString.stripLineEnd,count)
                        	}
                	case _ => ("",node.getFreq)
			//(start+node.getFreq.toString, node.getFreq) 
			}
		}		
	 	val ans = h(level,this)
		println(ans._1)
		}
 	def findCSNonceDomains(lenSubDomain: Int, thr: Double): Unit = {
		//var ans = List.empty[Option[String]]
		def h(lev: Int, tr: Double, dom:String, run: List[(String,Int,Int,Int)], node: T): List[(String,Int,Int,Int)] ={
			node match {
                       	case t: TrieNode => {
				if(lev == 0){
					val subs = t.children.values.map(_.getNumSubDomains).sum//.reduce(_+_)
					//if(subs > tr) 
						(dom,t.getFreq,t.children.size,subs)+:run
					//else run		
				}
				else{
					var ans = run
					for((p,kid)<-t.children) 
						ans = h(lev-1,tr,p+"."+dom,ans,kid)
					ans
				}	
                        }
                	case _ => run 
			}
		}
			//(dom+" Num subs "+t.children.size+" Tot instances: "+subs)+:run
		h(lenSubDomain,thr,"",List.empty[(String,Int,Int,Int)],this).sortBy(_._3).foreach(
			x=>println(x._1+" Num of instances where fqn "
				  +x._2+" Num child domains: "+x._3+
					" Tot instances: "+x._4))	
	} 
  }
  
  case object EmptyNode extends T{
   	var canEndHere = false
	def isEmpty: Boolean = true 
  	def search(list: List[String]): Boolean = false
  	def add(list: List[String], inFreq: Int): T ={
		//println("empty")
		if(list.isEmpty) EndNode(inFreq)
		else TrieNode(Map((list.head -> this.add(list.tail, inFreq))))
	}
	def getFreq = 0
  	def getNumSubDomains: Int = 0 
  } 
  

  case class EndNode(freq:Int) extends T{
   	var canEndHere = true
	def isEmpty: Boolean = true 
  	def search(list: List[String]): Boolean = list.isEmpty
  	def add(list: List[String], inFreq: Int): T ={
		//println(list.head)
		if(list.isEmpty) {
			val newFreq = inFreq + freq
			EndNode(newFreq) 
		}
		else TrieNode(Map((list.head -> EmptyNode.add(list.tail, inFreq))),true, freq) 
	}
	def getFreq = freq
  	def getNumSubDomains: Int = 1 
  } 

  case class TrieNode(children: Map[String,T], var canEndHere: Boolean = false, var freq: Int = 0) extends T{
	def isEmpty: Boolean = false
  	def search(list: List[String]): Boolean = {
    		if (list.isEmpty) canEndHere
    		else if (!children.contains(list.head)) false
    		else children(list.head).search(list.tail)
	}
  	def add(list: List[String], inFreq: Int): T = {
     	    //println(list.head)
	    if(list.isEmpty) this.copy(canEndHere=true, freq = this.freq+inFreq) 
	    else if(!children.contains(list.head)) this.copy(children = this.children+(list.head-> EmptyNode.add(list.tail, inFreq)))
	    else this.copy(children = this.children+(list.head-> this.children(list.head).add(list.tail, inFreq)))
      	    }
   	def getFreq = freq
	def getNumSubDomains: Int = {
                def h(node: T): Int ={
                        node match {
                        case t: TrieNode => t.getNumSubDomains
                        case _ => node.getFreq
                        }
                }
		getFreq+children.values.map(h(_)).sum//reduce(_+_)
	}
   }

  private var root: T = EmptyNode
  
  ///display/debugging functions below
  def toList = { 
    // make a list of all the strings in the set (in no particular order)
    root.mkList
  }
  
  // use toString if you just want to see what strings are in the set
  // use show if you want more details about the internal structure of the trie
  override def toString = toList.mkString("Trie(",",",")")
  def show: String = root.toString
  
}
val t = new DomainTrie



val raw = scala.io.Source.fromFile("cdx_query_freq.dns").getLines.toList.map(_.split(" "))
//val tups = raw.map(x=>(x.apply(0).reverse.split(".").toList, Integer.parseInt(x.apply(1))))

raw.foreach( x=>{t+=(x(0),x(1))})
//t.stats(4)

t.findCSNonceDomains(Integer.parseInt(args(0)),50)
