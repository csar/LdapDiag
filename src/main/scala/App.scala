import java.util
import javax.naming.{Context, NamingEnumeration}
import javax.naming.directory.{InitialDirContext, SearchControls}

import org.xbill.DNS.{ARecord, Lookup, SRVRecord, Type}

import scala.util.Try
import scala.util.control.NonFatal

object Run extends App {
  val env = new util.Hashtable[String, String]()
  val domain = if (args.length > 0) args(0) else "alis.test"
  val user = if (args.length > 1) args(1) else "carsten.saager"
  val pass = if (args.length > 2) args(2) else "Fr4nce!!"
  val searchString = if(args.length>3) args(3) else s"(&(objectClass=user)(sAMAccountName=$user))"
  import Context._

  env.put(INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
  env.put(SECURITY_AUTHENTICATION, "simple")
  env.put(SECURITY_PRINCIPAL, s"$user@$domain")
  env.put(SECURITY_CREDENTIALS, pass)

  println(s"In domain '$domain' user '$user' pass '$pass' search '$searchString'")
  println(checkLdap(domain, 389))
  val lookup = new Lookup("_ldap._tcp." + domain, Type.SRV)
  Try(lookup.run()).map { records =>
    for (record <- records.collect { case s: SRVRecord => s }) {
      println(record)
      val addr = new Lookup(record.getAdditionalName()).run().collect { case a: ARecord => a }
      if (addr.isEmpty) println("No IP resolved ")
      else for (ip <- addr) {
        println(checkLdap(ip.getAddress.getHostAddress, record.getPort))
      }

    }
  } recover {
    case NonFatal(_) =>
      println(s"DNS search for SRV records failed with '${lookup.getErrorString}'")
  }

  def checkLdap(ip: String, port: Int): Try[Int] = Try {
    env.put(PROVIDER_URL, s"ldap://$ip:$port")
    withResource( new InitialDirContext(env)) { context =>
      val searchControls = new SearchControls
      import SearchControls._
      searchControls.setReturningAttributes(Array("sAMAccountName"))
      searchControls.setSearchScope(SUBTREE_SCOPE)
      val searchBase = domain.split('.').mkString("DC=", ",DC=", "")

      val (values, time) = timed {
        context.search(searchBase, searchString, searchControls)
      }
      println(s"Query via $ip took ${time}ms")
      values
    }
  }

  def timed[T](call : => T):(T,Long) = {
    val start = System.currentTimeMillis()
    (call , System.currentTimeMillis() - start)
  }
  type UndeclaredClosable = {def close():Unit}
  def withResource[T<:UndeclaredClosable,R](res :  T)(body : T => R) = {
    try {
      body(res)
    } finally {
      res.close()
    }
  }
  implicit def enumCount(values: java.util.Enumeration[_]): Int = {

    var count = 0
    while (values.hasMoreElements) {
      count += 1
      values.nextElement()
    }
    values match {
      case a:UndeclaredClosable =>
        a.close()
      case _ =>
    }
    count
  }
}
