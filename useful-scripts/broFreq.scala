#!/usr/bin/env scala 

import scala.collection.immutable.{Map => IMap}
import scala.collection.mutable.{Map => MMap}
import scala.collection.immutable.TreeMap
import scala.collection.mutable.TreeSet




case class Field(id: String, ty: String){
	var size = 0
	var mean = 0.0
	var stdDev = 0.0
	var sortedFields = Array.empty[String]
	override def toString: String ={
		id+"\n"+freqMap.toString
	}
	var freqMap = MMap.empty[String, Int]
	def updateFreq(str: String): Unit = {
		if(!freqMap.contains(str)) size+=1
		val count = freqMap.getOrElse(str, 0)
		freqMap += (str -> (count+1))
	}
	def processStats: Unit = {
		this.mean = freqMap.values.sum/(1.0 *freqMap.size)
  		this.stdDev = math.sqrt(freqMap.values.map( x=>math.pow(x-mean,2)).sum /(1.0*freqMap.size -1.0)) 
		val l =freqMap.toList.sortBy(_._2).map(x=>x._1.toString+": "+x._2+", stdDevs: "+(x._2-mean)/stdDev)
		sortedFields=(l:::List("Average: "+mean,"StdDev: "+stdDev)).toArray
	}	

}




def printOutput(list: List[Field]): Unit = {
	println("#fields "+list.map(x=>x.id).mkString("\t"))//print fields
	println("#types "+list.map(x=>x.ty).mkString("\t"))//print types
	//print values
	val maxSize = list.head.size+2
	val ansArry = Array.fill(list.size)("")
	for(rIndex <- 0 until maxSize){
		for((field,cIndex) <- list.zipWithIndex){
			if(rIndex >= (field.size+2)){
				ansArry(cIndex) = "-"
			}
			else{
				ansArry(cIndex) = field.sortedFields(rIndex)

			}
		}
		println(ansArry.mkString("\t"))
	}
}


def processFile(lines: Iterator[String]): Unit = {
	var fields = lines.next.split("\t").toList 
	var types = lines.next.split("\t").toList 
	var idToField: IMap[Int,Field] = (fields.tail.zip(types.tail)).zipWithIndex.map(x=>(x._2->Field(x._1._1,x._1._2))).toMap
	//println(idToField)
	val fileWidth = idToField.size
	for(line <- lines){
		//println(line)
		val arry = line.split("\t").toArray
		if(arry(0) != "#close"){
			for(index <- 0 until fileWidth){
				//println(index)
				val field = idToField.getOrElse(index,???)
				field.updateFreq(arry(index))
			}
		}
	}
	idToField.values.foreach(x=>x.processStats)
	idToField -= 0 //remove ts from output TODO add flag
	idToField -= 1 //remove uid from output TODO add flag
	printOutput(idToField.values.toList.sortBy(x=>(-x.size)))
}

val lines = scala.io.Source.fromFile(args(0)).getLines

processFile(lines.drop(6))
