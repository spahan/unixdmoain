<?xml 
    version="1.0" 
    encoding="UTF-8"?>
<xsl:stylesheet 
    version="1.0"
    xmlns="http://www.w3.org/1999/xhtml"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:template match="node">
    <xsl:variable name="id" select="substring-after(substring-before(@id,','),'=')"/>
    <div class="node_tab" >
        <!-- we should really use fn:replace with regexp to remove all non-word-tokens. However, replace is only supported with XSLT v2.0 which ist not supported by many browsers by now. review this in 2015) -->
        <xsl:attribute name="id">tab_<xsl:value-of select="translate(@id,'- ,=.','_____')"/></xsl:attribute>
        <xsl:attribute name="dn"><xsl:value-of select="@id"/></xsl:attribute>
        <xsl:attribute name="shortname"><xsl:value-of select="$id"/></xsl:attribute>
        <div>
            <img ><xsl:attribute name="src">/ud2/images/<xsl:value-of select="@class"/>.png</xsl:attribute></img>
            <span style="font-size:large; font-weight:bold; padding-left:0.2em;"><xsl:value-of select="info/@name"/></span>
            <span style="font-size:small; font-style:italic; padding-left:0.5em;">(<xsl:value-of select="info/@dn"/>)</span>
            <img src="/ud2/images/note_edit.png" title="add a description for this host" onclick="addDescription(this)" style="float:right;"/>
        </div>
        <hr/>
        <xsl:apply-templates select="info"/>
        <hr/>
        <xsl:apply-templates select="settings">
            <xsl:sort select="name(.)" order="descending"/>
        </xsl:apply-templates>
    </div>
</xsl:template>

<!-- Detail infos about this node. -->
<xsl:template match="info">
    <table style="font-size:x-small; width:100%;" >
        <colgroup><col width="20%"/><col/><col width="5%"/></colgroup>
        <xsl:apply-templates mode="info"><xsl:sort select="name(.)"/></xsl:apply-templates>
    </table>
</xsl:template>
<!-- supress default output or we get uninteresting data into the output-->
<xsl:template match="info/*" mode="info">
    <!--<tr style="font-style:italic"><td><xsl:value-of select="name(.)"/></td><td><xsl:value-of select="."/></td><td/></tr>-->
</xsl:template>
<xsl:template match="info/ARecord" mode="info">
    <tr style="font-weight:bold;" title="the IP as reported by the host">
        <td>IPv4-address</td>
        <td><xsl:value-of select="."/></td>
        <td/>
    </tr>
</xsl:template>
<xsl:template match="info/USID" mode="info">
    <tr style="font-weight:bold;" title="The hosts unique ID as used in the kerberos database">
        <td>Unique Host ID</td>
        <td><xsl:value-of select="."/></td>
        <td/>
    </tr>
</xsl:template>
<xsl:template match="info/description" mode="info">
    <tr title="We recommend to at least specify the contact repsonsible for this host">
        <td>Description</td>
        <td><xsl:value-of select="."/></td>
        <td>
            <img src="/ud2/images/note_edit.png" onclick="editDescription(this)" title="edit the description"/>
            <img src="/ud2/images/delete.png" onclick="deleteDescription(this)" title="remove the description"/>
        </td>
    </tr>
</xsl:template>
<xsl:template match="info/lastSeen" mode="info">
    <tr title="This is the time when this host did connect to the database last time">
        <td>Last Seen</td>
        <td class="date">
            <span title="day"><xsl:value-of select="substring(.,6,2)"/></span>
            <span title="month"><xsl:value-of select="substring(.,4,2)"/></span>
            <span title="year">20<xsl:value-of select="substring(.,2,2)"/></span>
            <span title="hour">~<xsl:value-of select="substring(.,8,2)"/>:00</span>
        </td>
        <td/>
    </tr>
</xsl:template>

<!-- settings. These are the policy outputs. This is the main work area. -->
<xsl:template match="settings">
    <div class="policy_tab classes" title="ud Classes applied to this host">
        <xsl:call-template name="policy_table_head"/>
        <span>classes</span>
        <table style="display:none">
            <colgroup><col width="20%"/><col/></colgroup>
            <tr style="font-size:x-small;"><td>Class</td><td>source(s)</td></tr>
            <xsl:apply-templates select="/node/info/udGroup" mode="settings"/>
            <tr>
                <td/>
                <td>
                    <input placeholder="add a Class" type="text" name="classes"/>
                </td>
            </tr>
        </table>
    </div>
    <hr/>
    <div class="policy_tab userPolicy" title="posix users set for this host">
        <xsl:call-template name="policy_table_head"/>
        <span>userPolicy</span>
        <table style="display:none">
            <colgroup><col width="20%"/><col/></colgroup>
            <xsl:apply-templates select="userPolicy" mode="user"/>
            <xsl:apply-templates select="userPolicy" mode="group"/>
            <xsl:apply-templates select="userPolicy" mode="disable"/>
            <tr>
                <td/>
                <td>
                    <input placeholder="add a user" type="text" name="uid"/>
                    <input placeholder="add a group" type="text" name="gid"/>
                    <input placeholder="disable a user" type="text" name="disable"/>
                </td>
            </tr>
        </table>
    </div>
    <hr/>
    <div class="policy_tab groupPolicy" title="posix groups for this host; primary usr groups will be auto-added by the ud system.">
        <xsl:call-template name="policy_table_head"/>
        <span>groupPolicy</span>
        <table style="display:none">
            <colgroup><col width="20%"/><col/></colgroup>
            <xsl:apply-templates select="groupPolicy"/>
            <tr>
                <td/>
                <td><input placeholder="add a group" type="text" name="gid"/></td>
            </tr>
        </table>
    </div>
    <hr/>
    <div class="policy_tab cfPolicy" title="cf engine policy classes for this host">
        <xsl:call-template name="policy_table_head"/>
        <span>cfPolicy</span>
        <table style="display:none">
            <colgroup><col width="20%"/><col/></colgroup>
            <xsl:apply-templates select="cfPolicy"/>
            <tr>
                <td/>
                <td>
                    <input placeholder="add a cfpolicy" type="text" name="cfpol"/>
                    <input title="add a policy not in the list" placeholder="add free policy" type="text" name="fcpol"/>
                </td>
            </tr>
        </table>
    </div>
    <hr/>
    <div class="policy_tab sudoPolicy" title="posix users who have sudo rights. The ud system will only add users who actually are in userPolicy">
        <xsl:call-template name="policy_table_head"/>
        <span>sudoPolicy</span>
        <table style="display:none">
            <colgroup><col width="20%"/><col/></colgroup>
            <xsl:apply-templates select="aaaaPolicy" mode="user"/>
            <xsl:apply-templates select="aaaaPolicy" mode="group"/>
            <xsl:apply-templates select="aaaaPolicy" mode="disable"/>
            <tr>
                <td/>
                <td>
                    <input placeholder="add a sudoer" type="text" name="uid"/>
                    <input placeholder="add a sudo-group" type="text" name="gid"/>
                    <input placeholder="disable a user" type="text" name="disable"/>
                </td>
            </tr>
        </table>
    </div>
    <hr/>
    <div class="policy_tab localHomePolicy" title="path to local Home Directories for users. This will switch to *flat* hirarchy! If this is not set, the users will use Network Home Directories.">
        <xsl:call-template name="policy_table_head"/>
        <span>localHomePolicy</span>
        <table style="display:none">
            <colgroup><col width="20%"/><col/><col width="5%"/></colgroup>
            <tr>
                <xsl:variable name="localHome">
                    <xsl:value-of select="localHomePolicy/customPolicyData"/>
                </xsl:variable>
                <td>Path to local homes</td>
                <td><xsl:value-of select="$localHome"/></td>
                <td>
                    <xsl:choose>
                        <xsl:when test="localHomePolicy/customPolicyData">
                            <img src="/ud2/images/note_edit.png" onclick="editLocalHomePolicy(this)"/>
                            <img src="/ud2/images/delete.png" onclick="removePolicy(encodeURIComponent(getDN(this)), 'localHomePolicy', 'customPolicyData', this.parentNode.previousSibling.textContent);"/>
                        </xsl:when>
                        <xsl:otherwise>
                            <img src="/ud2/images/add.png" onclick="addLocalHomePolicy(this)"/>
                        </xsl:otherwise>
                    </xsl:choose>
                </td>
            </tr>
            <xsl:apply-templates select="localHomePolicy" mode="disable"/>
            <tr title="Users who shall not get local home directories (for example admins)">
                <td/>
                <td colspan="2"><input placeholder="disable a user" name="disable"/></td>
            </tr>
        </table>
    </div>
</xsl:template>

<xsl:template match="/node/info/udGroup" mode="settings">
    <tr>
        <td><xsl:value-of select="."/></td>
        <td>
            <xsl:apply-templates select="/node/sources/ud2/udGroup[@name=current()]"/>
        </td>
    </tr>
</xsl:template>

<xsl:template match="groupPolicy">
    <tr style="font-size:x-small;"><td>group</td><td>source(s)</td></tr>
    <xsl:for-each select="unixGroup">
         <tr>
            <td><xsl:value-of select="."/></td>
            <td>
                <xsl:apply-templates select="/node/sources/ud2/unixGroup[@name=current()]"/>
                <xsl:apply-templates select="/node/sources/policies/groupPolicy/unixGroup[.=current()]"/>
            </td>
        </tr>
    </xsl:for-each>
</xsl:template>

<xsl:template match="userPolicy" mode="user">
    <tr style="font-size:x-small;"><td>user</td><td>source(s)</td></tr>
    <xsl:for-each select="uid">
        <tr>
            <td><xsl:value-of select="."/></td>
            <td>
                <xsl:apply-templates select="/node/sources/ud2/uid[@name=current()]"/>
                <xsl:apply-templates select="/node/sources/policies/userPolicy/uid[.=current()]"/>
            </td>
        </tr>
    </xsl:for-each>
</xsl:template>
<xsl:template match="userPolicy" mode="group">
    <tr style="font-size:x-small;"><td>group</td><td>source(s)</td></tr>
    <xsl:for-each select="unixGroup">
        <tr>
            <td><xsl:value-of select="."/></td>
            <td>
                <xsl:apply-templates select="/node/sources/policies/userPolicy/unixGroup[.=current()]"/>
            </td>
        </tr>
    </xsl:for-each>
</xsl:template>
<xsl:template match="userPolicy" mode="disable">
    <tr style="font-size:x-small;"><td>disabled users</td><td>source(s)</td></tr>
    <xsl:for-each select="disabledPolicyData">
        <tr>
            <td><xsl:value-of select="."/></td>
            <td>
                <xsl:apply-templates select="/node/sources/policies/userPolicy/disabledPolicyData[.=current()]"/>
            </td>
        </tr>
    </xsl:for-each>
</xsl:template>

<xsl:template match="aaaaPolicy" mode="user">
    <tr style="font-size:x-small;"><td>user</td><td>source(s)</td></tr>
    <xsl:for-each select="uid">
        <tr>
            <td><xsl:value-of select="."/></td>
            <td>
                <xsl:apply-templates select="/node/sources/policies/sudoPolicy/uid[.=current()]"/>
            </td>
        </tr>
    </xsl:for-each>
</xsl:template>
<xsl:template match="aaaaPolicy" mode="group">
    <tr style="font-size:x-small;"><td>group</td><td>source(s)</td></tr>
    <xsl:for-each select="unixGroup">
        <tr>
            <td><xsl:value-of select="."/></td>
            <td>
                <xsl:apply-templates select="/node/sources/policies/sudoPolicy/unixGroup[.=current()]"/>
            </td>
        </tr>
    </xsl:for-each>
</xsl:template>
<xsl:template match="aaaaPolicy" mode="disable">
    <tr style="font-size:x-small;"><td>disabled users</td><td>source(s)</td></tr>
    <xsl:for-each select="disabledPolicyData">
        <tr>
            <td><xsl:value-of select="."/></td>
            <td>
                <xsl:apply-templates select="/node/sources/policies/sudoPolicy/disabledPolicyData[.=current()]"/>
            </td>
        </tr>
    </xsl:for-each>
</xsl:template>

<xsl:template match="cfPolicy">
    <tr style="font-size:x-small;"><td>policy</td><td>source(s)</td></tr>
    <xsl:for-each select="policyClass">
        <tr>
            <td><xsl:value-of select="."/></td>
            <td>
                <xsl:apply-templates select="/node/sources/ud2/policyClass[@name=current()]"/>
                <xsl:apply-templates select="/node/sources/policies/cfPolicy/policyClass[.=current()]"/>
            </td>
        </tr>
    </xsl:for-each>
</xsl:template>

<xsl:template match="localHomePolicy" mode="disable">
    <tr style="font-size:x-small;" title="Users who shall not get local home directories (for example admins)">
        <td>disabled users</td>
        <td colspan="2">source(s)</td>
    </tr>
    <xsl:for-each select="disabledPolicyData">
        <tr title="Users who shall not get local home directories (for example admins)">
            <td><xsl:value-of select="."/></td>
            <td colspan="2">
                <xsl:apply-templates select="/node/sources/policies/localHomePolicy/disabledPolicyData[.=current()]"/>
            </td>
        </tr>
    </xsl:for-each>
</xsl:template>

<!-- helpers -->
<xsl:template match="sources/ud2/*">
<!-- this one creates the link to the source of the policy -->
    <span class="sourceLink">
        <a>
            <xsl:attribute name="title">legacy attribute in container</xsl:attribute>
            <xsl:attribute name="onclick">
                $.get('/domad/node/' + encodeURIComponent(
                '<xsl:value-of select="."/>'
                ), false, false, 'xml').success(show_details);
            </xsl:attribute>
            <xsl:value-of select="substring-after(substring-before(current(),','), '=')"/>
        </a>
        <xsl:if test="current() = /node/@id">
            <img src="images/delete.png" class="removeButton">
             <xsl:attribute name="onclick">
                $.ajax({
                    type: 'POST',
                    url: '/domad/node/' + encodeURIComponent('<xsl:value-of select="."/>'),
                    data: {
                        action:'delete',
                        attribute:'<xsl:value-of select="name(.)"/>', 
                        value: this.parentNode.parentNode.parentNode.firstChild.textContent
                    },
                    success: function() {
                        $.ajax({
                            type:'GET', 
                            url:'/domad/node/' + encodeURIComponent('<xsl:value-of select="."/>'), 
                            dataType:'xml', 
                            success:show_details
                        });
                    }
                });
                event.preventDefault();
            </xsl:attribute>
            </img>
        </xsl:if>
    </span>
</xsl:template>
<xsl:template match="sources/policies/*/*">
    <span class="sourceLink">
        <a>
            <xsl:attribute name="title">udPolicy Setting</xsl:attribute>
            <xsl:attribute name="onclick">
                $.get('/domad/node/' + encodeURIComponent(
                '<xsl:value-of select="../@src"/>'
                ), false, false, 'xml').success(show_details);
            </xsl:attribute>
            <xsl:value-of select="substring-after(substring-before(../@src,','), '=')"/>
        </a>
        <xsl:if test="../@src = /node/@id">
            <img src="images/delete.png" class="removeButton">
                <xsl:attribute name="onclick">
                    removePolicy(
                        encodeURIComponent(getDN(this)),
                        '<xsl:value-of select="name(..)"/>',
                        '<xsl:value-of select="name(.)"/>',
                        this.parentNode.parentNode.parentNode.firstChild.textContent);
                    event.preventDefault();
                </xsl:attribute>
            </img>
        </xsl:if>
    </span>
</xsl:template>

<!-- creates the heads for the policy tabs in the node details. can be hidden -->
<xsl:template name="policy_table_head">
    <img src="images/indicator.png" 
        class=""
        style="padding: 4px 4px 0 0;"/>
    <img src="images/open_indicator.png" 
        class="hidden"
        style="padding: 4px 4px 0 0;"/>
</xsl:template>

</xsl:stylesheet>
