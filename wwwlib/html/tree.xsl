<?xml 
    version="1.0" 
    encoding="UTF-8"?>
<xsl:stylesheet 
    version="1.0"
    xmlns="http://www.w3.org/1999/xhtml"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:template match="*">
    <li>
         <xsl:attribute name="dn"><xsl:value-of select="@id"/></xsl:attribute>
        <div>
            <xsl:attribute name="class"><xsl:value-of select="name(current())"/></xsl:attribute>
            <xsl:call-template name="makeNodeTitle"/>
            <button class="tree_actions"/>
        </div>
        <ul>
            <xsl:apply-templates>
                <xsl:sort select="name()" order="descending"/>
                <xsl:sort select="@id"/>
            </xsl:apply-templates>
        </ul>
    </li>
</xsl:template>

<xsl:template name="makeNodeTitle">
    <img>
        <xsl:attribute name="src">images/<xsl:value-of select="name(current())"/>.png</xsl:attribute>
    </img>
    <span>
        <xsl:attribute name="title"><xsl:value-of select="@description"/></xsl:attribute>
        <xsl:value-of select="@name"/>
    </span>
</xsl:template>

</xsl:stylesheet>
