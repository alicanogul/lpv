require 'socket'
require 'openssl'
require 'thread'
require 'openssl'
require 'base64'
require 'rubygems'  
require 'active_record' 
require 'fileutils'
require 'bcrypt'
require './encrypto_signo.rb'
ActiveRecord::Base.establish_connection(  
:adapter=> "mysql2",  
:host => "localhost",  
:database=> "lpv",
:username=> "root",
:password => "codefellas"
)  
  

class Users < ActiveRecord::Base  
end  

class Userkey < ActiveRecord::Base  
end 

class Storedpasswords < ActiveRecord::Base  
end  

class Accesslist < ActiveRecord::Base  
end

class Group < ActiveRecord::Base  
end

class Groupacclist < ActiveRecord::Base  
end

class Globalcap < ActiveRecord::Base  
end

class Domaincap < ActiveRecord::Base  
end

class Groupcap < ActiveRecord::Base  
end

unless ARGV.length == 2
  puts "Usage: ruby #{__FILE__} port ssl_cert_file"
  exit 1
end

$shkey
$state = 0
$storestate=0
$decshstate=0
$gpstate=0
$rdstate=0
$allowstate=0
$revokestate=0
$atgstate=0
$rfgstate=0
$agstate=0
$cpstate=0
$dustate=0
$dgstate=0
$addgrstate=0
$agcstate=0
$adcstate=0
$agrcstate=0

def createUserkey(userName)
  	FileUtils.mkdir_p "#{userName}"
	system("openssl genrsa -out ./#{userName}/private.key 4096")
	priv= OpenSSL::PKey::RSA.new(File.read("./#{userName}/private.key"))
	system("openssl rsa -pubout -in ./#{userName}/private.key -out ./#{userName}/public.key")
	public_key  = OpenSSL::PKey::RSA.new(File.read("./#{userName}/public.key")) 
	File.delete "./#{userName}/public.key"
	Userkey.create(:username => userName, :public_key=> public_key, :key_type=> "RSA")
end

def createCipherText(password)
	system("openssl genrsa -out ./shared.key 512")
	$shkey = File.read("shared.key")
	File.delete "shared.key" 
	ciphertext = EncryptoSigno.encrypt($shkey, password)
	return ciphertext
end

def storepass(dom, cipass)
   	gc=Globalcap.find_by(username: $userName)
  	if(gc.adddomain==false)
		return "You are not authorized"
   	end
    stpass = Storedpasswords.find_by(domain: dom)
    if (stpass!=nil)
    	return "Domain exists"
  	else
		Storedpasswords.create(:domain => dom, :description=> nil, :cyphered_pass=> createCipherText(cipass))
		if($userName=="admin")
			Domaincap.create(:domain=>dom, :username=> $userName, :changepass=>1, :allow=>1, :allowgroup=>1, :revokepass=>1, :deldomain=>1, :adjust=>1)
		else
			Domaincap.create(:domain=>dom, :username=> $userName, :changepass=>0, :allow=>0, :allowgroup=>0, :revokepass=>0, :deldomain=>0, :adjust=>0)
		end
		return "Stored"
	end
end

def createEncSharedKey(public_key, shared_key)
	#File.write('public.key', public_key)
 	#public_key_file = 'public.key';
    p_key = OpenSSL::PKey::RSA.new(public_key)
    encrypted_string = Base64.encode64(p_key.public_encrypt(shared_key))
	return encrypted_string
end

def hasaccess(dom, userName, key)
	Accesslist.create(:domain => dom, :username=> userName, :cyphered_key=> createEncSharedKey(key, $shkey))
end

def getDecSharedKey(dom) #gets logged in user's decrypted shared key
	user = Accesslist.find_by(domain: dom, username: $userName)
	if(user==nil)
		return "nd"
	end
	private_key = OpenSSL::PKey::RSA.new(File.read("./#{$userName}/private.key"))
	string = private_key.private_decrypt(Base64.decode64(user.cyphered_key))
	return string
end

def getPass(dom)
	sh=getDecSharedKey(dom)
	if(sh=="nd")
		return "You can't access this domain"
	end
	stpass = Storedpasswords.find_by(domain: dom)
	decpass = EncryptoSigno.decrypt(sh, stpass.cyphered_pass)
	return decpass
end

def removedom(dom)
	gc=Globalcap.find_by(username: $userName)
	dc=Domaincap.find_by(domain: dom, username: $userName)
  	if(gc.deldomain==true)
		Storedpasswords.find(dom).destroy  
		Accesslist.connection.execute("DELETE FROM accesslists WHERE domain=\"#{dom}\";")
		Groupacclist.connection.execute("DELETE FROM groupacclists WHERE domain=\"#{dom}\";")
		Domaincap.connection.execute("DELETE FROM domaincaps WHERE domain=\"#{dom}\";")
		return "Domain removed"
   	end
	if(dc==nil)
		return "You are not authorized"
	end
	if(dc.deldomain==true)
		Storedpasswords.find(dom).destroy  
		Accesslist.connection.execute("DELETE FROM accesslists WHERE domain=\"#{dom}\";")
		Groupacclist.connection.execute("DELETE FROM groupacclists WHERE domain=\"#{dom}\";")
		Domaincap.connection.execute("DELETE FROM domaincaps WHERE domain=\"#{dom}\";")
		return "Domain removed"
   	end
	return "You are not authorized"
end

def allow(uname, dname)
	if($userName==uname)
		return "You can't allow yourself"
	end
	al=Accesslist.find_by(domain: dname, username: uname)
	if(al!=nil)
		return "Already allowed"
	end
	sp = Storedpasswords.find_by(domain: dname)
	if(sp==nil)
		return "There is no such domain"
	end
	s=getDecSharedKey(dname)
	usr= Userkey.find_by(username: uname)
	if(usr==nil)
		return "There is no such user"
	end
	dc=Domaincap.find_by(domain: dname, username: $userName)
	if(dc.allow==false)
		return "You are not authorized"
	end
	es=createEncSharedKey(usr.public_key, s)	
	Accesslist.create(:domain => dname, :username=> uname, :cyphered_key=> es)
	if(uname=="admin")
			Domaincap.create(:domain=>dname, :username=> uname, :changepass=>1, :allow=>1, :allowgroup=>1, :revokepass=>1, :deldomain=>1, :adjust=>1)
	else
			Domaincap.create(:domain=>dname, :username=> uname, :changepass=>0, :allow=>0, :allowgroup=>0, :revokepass=>0, :deldomain=>0, :adjust=>0)
	end
	return "Access allowed"
end

def revokepass(uname, dname)
	al=Accesslist.find_by(domain: dname, username: uname)
	if(al==nil)
		return "Domain or user not found"
	end
	dc=Domaincap.find_by(domain: dname, username: $userName)
	if(dc.revokepass==false)
		return "You are not authorized"
	end
	Accesslist.connection.execute("DELETE FROM accesslists WHERE domain=\"#{dname}\" AND username=\"#{uname}\";")
	acl=Accesslist.find_by(domain: dname)
	if(acl==nil)
		Storedpasswords.find(dname).destroy
	end
	return "Revoked"
end

def addtogroup(uname, gname)
	u=Users.find_by(username: uname)
	if(u==nil)
		return "User not found"
	end
	gr=Group.find_by(groupname: gname)
	if(gr==nil)
		return "Group not found"
	end
	grr=Group.find_by(username: $userName, groupname: gname)
	if(grr==nil)
		return "You are not in this group"
	end
	grc=Groupcap.find_by(username: $userName, groupname: gname)
	if(grc.addtogroup==false)
		return "You are not authorized"
	end
	g=Group.find_by(username: uname, groupname: gname)
	if(g!=nil)
		return "Already added"
	end
	Group.create(:username => uname, :groupname => gname)
	if(uname=="admin")
		Groupcap.create(:username=> uname, :groupname=> gname, :addtogroup=> 1, :removefromgroup=>1, :delgroup=>1, :adjust=>1)
	else
		Groupcap.create(:username=> uname, :groupname=> gname, :addtogroup=> 0, :removefromgroup=>0, :delgroup=>0, :adjust=>0)
	end
	gal=Groupacclist.where(groupname: gname)
	gal.each do |row|
		allow(uname, row.domain)
	end
	return "Added to group"
end

def removefromgroup(uname, gname)
	grr=Group.find_by(username: $userName, groupname: gname)
	if(grr==nil)
		return "You are not in this group"
	end
	g=Group.where(username: uname, groupname: gname)
	if(g.count==0)
		return "No user in this group"
	end
	grc=Groupcap.find_by(username: $userName, groupname: gname)
	if(grc.removefromgroup==false)
		return "You are not authorized"
	end
	Group.connection.execute("DELETE FROM groups WHERE username=\"#{uname}\" AND groupname=\"#{gname}\";")
	gal=Groupacclist.where(groupname: gname)
	if(gal.count!=0)
		gal.each do |row|
			revokepass(uname, row.domain)
		end
	end
	return "Removed from group"
end

def allowgroup(gname, dname)
	g=Group.where(groupname: gname)
	if(g.count==0)
		return "No group"
	end
	d=Storedpasswords.where(domain: dname)
	if(d.count==0)
		return "No domain"
	end
	gp=getPass(dname)
	if(gp=="You can't access this domain")
		return "You can't access this domain"
	end
	gal=Groupacclist.find_by(groupname: gname, domain: dname)
	if(gal!=nil)
		return "Already allowed"
	end
    dc=Domaincap.find_by(domain: dname, username: $userName)
	if(dc.allowgroup==false)
		return "You are not authorized"
	end
	g.each do |row|
	  allow(row.username, dname)
	end
	Groupacclist.create(:groupname => gname, :domain => dname)
	return "Group is allowed"
end

def changepass(dname, pass)
	stpass = Storedpasswords.find_by(domain: dname)
    if (stpass==nil)
    	return "Domain doesn't exist"
  	end
	al=Accesslist.find_by(domain: dname, username: $userName)
	if(al==nil)
		return "You are not authorized"
	end
	dc=Domaincap.find_by(domain: dname, username: $userName)
	if(dc.changepass==false)
		return "You are not authorized"
	end
	cipass=createCipherText(pass)
	Storedpasswords.connection.execute("UPDATE storedpasswords SET cyphered_pass=\"#{cipass}\" WHERE domain=\"#{dname}\";")
	al=Accesslist.where(domain: dname)
	al.each do |row|
		usr=row.username
		pubkey= Userkey.find_by(username: usr)
		cykey=createEncSharedKey(pubkey.public_key, $shkey)
		Accesslist.connection.execute("UPDATE accesslists SET cyphered_key=\"#{cykey}\" WHERE username=\"#{usr}\";")
	end
	return "Changed"

end

def deluser(uname)
   	usr=Globalcap.find_by(username: $userName)
  	if(usr.deluser==false)
		return "You are not authorized"
   	end
	u=Users.find_by(username: uname)
	if(u==nil)
		return "User not found"
	end
	Users.connection.execute("DELETE FROM users WHERE username=\"#{uname}\";")
	Userkey.connection.execute("DELETE FROM userkeys WHERE username=\"#{uname}\";")
	Accesslist.connection.execute("DELETE FROM accesslists WHERE username=\"#{uname}\";")
	Group.connection.execute("DELETE FROM groups WHERE username=\"#{uname}\";")
	Globalcap.connection.execute("DELETE FROM globalcaps WHERE username=\"#{uname}\";")
	Domaincap.connection.execute("DELETE FROM domaincaps WHERE username=\"#{uname}\";")
	Groupcap.connection.execute("DELETE FROM groupcaps WHERE username=\"#{uname}\";")
	return "User deleted"
end

def delgroup(gname)
	gc=Globalcap.find_by(username: $userName)
	grc=Groupcap.find_by(username: $userName, groupname: gname)
	g=Group.find_by(groupname: gname)
	if(g==nil)
		return "Group not found"
	end
  	if(gc.delgroup==true)
		Group.connection.execute("DELETE FROM groups WHERE groupname=\"#{gname}\";")
		Groupacclist.connection.execute("DELETE FROM groupacclists WHERE groupname=\"#{gname}\";")
		Groupcap.connection.execute("DELETE FROM groupcaps WHERE groupname=\"#{gname}\";")
		return "Group deleted"
   	end
	if(grc==nil)
		return "You are not authorized"
	end
	if(grc.delgroup==true)
		Group.connection.execute("DELETE FROM groups WHERE groupname=\"#{gname}\";")
		Groupacclist.connection.execute("DELETE FROM groupacclists WHERE groupname=\"#{gname}\";")
		Groupcap.connection.execute("DELETE FROM groupcaps WHERE groupname=\"#{gname}\";")
		return "Group deleted"
   	end
	return "You are not authorized"

end

def addgroup(gname)
	gc=Globalcap.find_by(username: $userName)
  	if(gc.addgroup==false)
		return "You are not authorized"
   	end
	g=Group.find_by(groupname: gname)
	if(g!=nil)
		return "Group exists"
	end
	Group.create(:username => $userName, :groupname => gname)
	if($userName=="admin")
		Groupcap.create(:username=> $userName, :groupname=> gname, :addtogroup=> 1, :removefromgroup=>1, :delgroup=>1, :adjust=>1)
	else
		Groupcap.create(:username=> $userName, :groupname=> gname, :addtogroup=> 0, :removefromgroup=>0, :delgroup=>0, :adjust=>0)
	end
	return "Group added"
end

def adjustglcaps(uname, feature, tf)
	gc=Globalcap.find_by(username: $userName)
	if(gc.adjust==false)
		return "You are not authorized"
   	end
	Globalcap.connection.execute("UPDATE globalcaps SET #{feature}=\"#{tf}\" WHERE username=\"#{uname}\";")
	return "Adjusted"
end

def adjustdomcaps(uname, dname, feature, tf)
	dc=Domaincap.find_by(domain: dname, username: $userName)
	if(dc.adjust==false)
		return "You are not authorized"
   	end
	Domaincap.connection.execute("UPDATE domaincaps SET #{feature}=\"#{tf}\" WHERE domain=\"#{dname}\" AND username=\"#{uname}\";")
	return "Adjusted"
end

def adjustgroupcaps(uname, gname, feature, tf)
	grc=Groupcap.find_by(username: $userName, groupname: gname)
	if(grc.adjust==false)
		return "You are not authorized"
   	end
	Groupcap.connection.execute("UPDATE groupcaps SET #{feature}=\"#{tf}\" WHERE username=\"#{uname}\" AND groupname=\"#{gname}\";")
	return "Adjusted"
end

client  = TCPSocket.new '127.0.0.1', ARGV[0]
context = OpenSSL::SSL::SSLContext.new
context.verify_mode = OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
context.ca_file = ARGV[1]

secure = OpenSSL::SSL::SSLSocket.new(client, context)
secure.sync_close = true
secure.connect

Thread.new do
  begin
    while response = secure.gets
      response = response.chomp

      #Take action
      if (response == "quit")
        secure.sysclose
        Kernel.abort()
      end


	  if(response == "Enter your username and password to login")
	 	$stdout.puts  "Enter your username and password to login"
	  	next

	  elsif(response == "Please enter your username and password to login! (<username> <password>)")
		$stdout.puts  "Please enter your username and password to login! (<username> <password>)"
		next

	  elsif(response == "Wrong username or password")
		$stdout.puts  "Wrong username or password"
		next

	  elsif(response=="User password is changed")
		$stdout.puts "User password is changed"
		next

	  elsif(response == "Unknown Command!")
		$stdout.puts  "Unknown Command!"
		next

	  elsif(response == "help")
		$stdout.puts  "Commands:\nadduser [username] [password]: Adds the user to the database.\ndeluser [username]: Deletes the user from the database.\nchangeuserpass [password]: Changes the logged in user's password.\nstorepass [domain] [password]: Stores domain and its password to the database.\ngetpass [domain]: Gets domain's password.\nchangepass [domain] [password]: Changes domain's password.\nallow [username] [domain]: Allows specified user to access the specified domain's password.\nrevokepass [username] [domain]: Revokes the specified user's access to the domain.\nremovedom [domain]: Removes domain from database.\naddgroup [group name]: Adds the user group to the database.\naddtogroup [username] [group name]: Adds the user to the group.\nallowgroup [group name] [domain]: Allow all of the users of the group to access the domain's password.\nremovefromgroup [username] [groupname]: Removes the specified user from the specified group.\ndelgroup [group name]: Deletes the group from database.\nadjustglcaps [username] [feature] [boolean value]: Adjusts the specified user's capability to use the specified feature globally.\nadjustdomcaps [username] [domain] [feature] [boolean value]: Adjusts the specified user's capability to use the specified feature on the specified domain.\nadjustgroupcaps [username] [group name] [feature] [boolean value]: Adjusts the specified user's capability to use the specified feature on the specified group.\nquit: Quits the program."
		next

	  elsif ($state == 0 && response == "logged in")
        $state = 1 #wait for userName
        next

      elsif ($state == 1)
		$state = 2
        $userName = response
		userkey = Userkey.find_by(username: $userName)
		#$stdout.puts "#{$shkey}"
		if(userkey==nil)
			createUserkey($userName)
		end
		$stdout.puts "Welcome #{$userName}"
        next
	  end


	  if(response=="User added")
		$stdout.puts "User added"
		next
	  elsif(response=="User exists")
		$stdout.puts "User exists"
		next
	  elsif(response=="You aren't authorized")
		$stdout.puts "You aren't authorized"
		next
	  end

	  if (response == "adjustglcaps")
		$agcstate=1
		next

	  elsif($agcstate==1)
		uname=response
		$agcstate=2
		next

	  elsif($agcstate==2)
		feature=response
		$agcstate=3
		next

	  elsif($agcstate==3)
		$agcstate=4
		tf=response
		aa=adjustglcaps(uname, feature, tf)
        $stdout.puts aa
		next
	  end

	  if (response == "adjustdomcaps")
		$adcstate=1
		next

	  elsif($adcstate==1)
		uname=response
		$adcstate=2
		next

	  elsif($adcstate==2)
		dname=response
		$adcstate=3
		next

	  elsif($adcstate==3)
		feature=response
		$adcstate=4
		next

	  elsif($adcstate==4)
		$adcstate=5
		tf=response
		aa=adjustdomcaps(uname, dname, feature, tf)
        $stdout.puts aa
		next
	  end

	  if (response == "adjustgroupcaps")
		$agrcstate=1
		next

	  elsif($agrcstate==1)
		uname=response
		$agrcstate=2
		next

	  elsif($agrcstate==2)
		gname=response
		$agrcstate=3
		next

	  elsif($agrcstate==3)
		feature=response
		$agrcstate=4
		next

	  elsif($agrcstate==4)
		$agrcstate=5
		tf=response
		aa=adjustgroupcaps(uname, gname, feature, tf)
        $stdout.puts aa
		next
	  end

	  if (response == "storepass")
		$storestate=1
		next

	  elsif($storestate==1)
		$domname=response
		$storestate=2
		next

	  elsif($storestate==2)
		$storestate=3
		$dompass=response
		k= storepass($domname, $dompass)
		$stdout.puts k
		if(k=="Domain exists")
			next
		end
		if(k=="You are not authorized")
			next
		end
		usr = Userkey.find_by(username: $userName)
		pubkey= usr.public_key
		hasaccess($domname, $userName, pubkey)
		next
	  end


	  if (response == "allow")
		$allowstate=1
		next

	  elsif($allowstate==1)
		uname=response
		$allowstate=2
		next

	  elsif($allowstate==2)
		$allowstate=3
		dname=response
		aa=allow(uname, dname)
        $stdout.puts aa
		next
	  end
	

 	 if (response == "revokepass")
		$revokestate=1
		next

	  elsif($revokestate==1)
		uname=response
		$revokestate=2
		next

	  elsif($revokestate==2)
		$revokestate=3
		dname=response
		aa=revokepass(uname, dname)
        $stdout.puts aa
		next
	  end

	  if (response == "addtogroup")
		$atgstate=1
		next

	  elsif($atgstate==1)
		uname=response
		$atgstate=2
		next

	  elsif($atgstate==2)
		$atgstate=3
		gname=response
		aa=addtogroup(uname, gname)
        $stdout.puts aa
		next
	  end

	  if (response == "removefromgroup")
		$rfgstate=1
		next

	  elsif($rfgstate==1)
		uname=response
		$rfgstate=2
		next

	  elsif($rfgstate==2)
		$rfgstate=3
		gname=response
		aa=removefromgroup(uname, gname)
        $stdout.puts aa
		next
	  end

	  if (response == "allowgroup")
		$agstate=1
		next

	  elsif($agstate==1)
		gname=response
		$agstate=2
		next

	  elsif($agstate==2)
		$agstate=3
		dname=response
		aa=allowgroup(gname, dname)
        $stdout.puts aa
		next
	  end

	  if (response == "changepass")
		$cpstate=1
		next

	  elsif($cpstate==1)
		dname=response
		$cpstate=2
		next

	  elsif($cpstate==2)
		$cpstate=3
		pass=response
		aa=changepass(dname, pass)
        $stdout.puts aa
		next
	  end
		
	  if(response=="getpass")
		$gpstate=1
		next

	  elsif($gpstate==1)
		$gpstate=2
		dom=response
		aa=getPass(dom)
        $stdout.puts aa
		next
	  end
	  

	  if(response=="removedom")
		$rdstate=1
		next

	  elsif($rdstate==1)
		$rdstate=2
		dom=response
		aa=removedom(dom)
		$stdout.puts aa
		next
	  end

 	  if(response=="deluser")
		$dustate=1
		next

	  elsif($dustate==1)
		$dustate=2
		user=response
		aa=deluser(user)
		$stdout.puts aa
		if($userName==user)
		    FileUtils.rm_rf("#{user}")
			Kernel.abort()
		end
		next
	  end

	  if(response=="delgroup")
		$dgstate=1
		next

	  elsif($dgstate==1)
		$dgstate=2
		group=response
		aa=delgroup(group)
		$stdout.puts aa
		next
	  end

	  if(response=="addgroup")
		$addgrstate=1
		next

	  elsif($addgrstate==1)
		$addgrstate=2
		group=response
		aa=addgroup(group)
		$stdout.puts aa
		next
	  end

    end
  rescue
    $stderr.puts "Error from client: #{$!}"
  end
end

while request = $stdin.gets
  request = request.chomp
  secure.puts request
end
