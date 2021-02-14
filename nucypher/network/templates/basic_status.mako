<%!
def hex_to_rgb(color_hex):
    # Expects a color in the form "#abcdef"
    r = int(color_hex[1:3], 16)
    g = int(color_hex[3:5], 16)
    b = int(color_hex[5:7], 16)
    return r, g, b

def rgb_to_hex(r, g, b):
    return f"#{r:02x}{g:02x}{b:02x}"

def contrast_color(color_hex):
    r, g, b = hex_to_rgb(color_hex)
    # As defined in https://www.w3.org/WAI/ER/WD-AERT/#color-contrast
    # Ranges from 0 to 255
    intensity = (r * 299 + g * 587 + b * 114) / 1000
    if intensity > 128:
        return "black"
    else:
        return "white"

def character_span(character):
    return f'<span class="symbol" style="color: {contrast_color(character.color_hex)}; background-color: {character.color_hex}">{character.symbol}</span>'
%>

<%def name="fleet_state_icon(checksum, nickname, population)">
%if not checksum:
NO FLEET STATE AVAILABLE
%else:
<table class="state-info" title="${nickname}">
    <tr>
        <td>
            ## Need to compose these spans as strings to avoid introducing whitespaces
            <span class="state-icon">${"".join(character_span(character) for character in nickname.characters)}</span>
        </td>
        <td>
            <span>${population} nodes</span>
            <br/>
            <span class="checksum">${checksum[0:8]}</span>
        </td>
    </tr>
</table>
%endif
</%def>


<%def name="fleet_state_icon_from_state(state)">
${fleet_state_icon(state.checksum, state.nickname, len(state.nodes))}
</%def>


<%def name="fleet_state_icon_from_known_nodes(state)">
${fleet_state_icon(state.checksum, state.nickname, state.population())}
</%def>


<%def name="node_info(node)">
<div>
    <table class="node-info">
        <tr>
            <td>
                ## Need to compose these spans as strings to avoid introducing whitespaces
                <span class="node-icon">${"".join(character_span(character) for character in node.nickname.characters)}</span>
            </td>
            <td>
                <a href="https://${node.rest_interface}/status">
                <span class="nickname">${ node.nickname }</span>
                </a>
                <br/>
                <span class="checksum">${ node.checksum_address }</span>
            </td>
        </tr>
    </table>
</div>
</%def>


<%def name="main()">
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <link rel="icon" type="image/x-icon" href="https://www.nucypher.com/favicon-32x32.png"/>
    <link rel="stylesheet" type="text/css" href="https://fonts.googleapis.com/css?family=Open+Sans" />
</head>
<style type="text/css">

    body {
        font-family: "Open Sans", sans-serif;
        margin: 2em 2em 2em 2em;
    }

    /* unvisited link */
    a:link {
        color: #115;
        text-decoration-color: #bbb;
    }

    /* visited link */
    a:visited {
        color: #626;
    }

    table.node-info > tr > td {
        padding: 0 0em;
    }

    table.state-info {
        float: left;
        padding: 0 1em 0 0;
    }

    table.state-info > tr > td {
        padding: 0 0em;
    }

    table.known-nodes > tbody > tr > td {
        padding: 0 1em 0 0;
    }

    table.known-nodes > thead > tr > td {
        border-bottom: 1px solid #ddd;
    }

    table.known-nodes > tbody > tr > td {
        border-bottom: 1px solid #ddd;
    }

    .this-node-info {
        margin-bottom: 2em;
    }

    h3 {
        margin-bottom: 0em;
    }

    .this-node {
        font-size: x-large;
    }

    .nickname {
        font-weight: bold;
    }

    .node-icon {
        font-size: 2em;
        font-family: monospace;
        margin-right: 0.2em;
    }

    .state-icon {
        font-size: 2em;
        font-family: monospace;
        margin-right: 0.2em;
    }

    .symbol {
        padding-left: 0.05em;
        padding-right: 0.05em;
    }

    .checksum {
        font-family: monospace;
    }
</style>
</body>

    <table class="this-node-info">
        <tr>
            <td></td>
            <td><div class="this-node">${node_info(this_node)}</div></td>
        </tr>
        <tr>
            <td><div style="margin-bottom: 1em"></div></td>
            <td></td>
        </tr>
        <tr>
            <td><i>Running:</i></td>
            <td>v${ version }</td>
        </tr>
        <tr>
            <td><i>Domain:</i></td>
            <td>${ domain }</td>
        </tr>
        <tr>
            <td><i>Fleet state:</i></td>
            <td>${fleet_state_icon_from_known_nodes(this_node.known_nodes)}</td>
        </tr>
        <tr>
            <td><i>Previous states:</i></td>
            <td>
                %for state in previous_states:
                    ${fleet_state_icon_from_state(state)}
                %endfor
            </td>
        </tr>
    </table>

    <h3>${len(known_nodes)} ${"known node" if len(known_nodes) == 1 else "known nodes"}:</h3>

    %for label in buckets:
        <table class="known-nodes">
            <thead>
            <td>${str(label)} Bucket</td>
            <td>Launched</td>
            <td>Last Seen</td>
            <td>Fleet State</td>
            </thead>
            <tbody>
                %for node in known_nodes.get_nodes(label=str(label)):
                    <tr>
                        <td>${node_info(node)}</td>
                        <td>${ node.timestamp }</td>
                        <td>${ node.last_seen }</td>
                        <td>${fleet_state_icon(node.fleet_state_checksum,
                        node.fleet_state_nickname,
                        node.fleet_state_population)}</td>
                    </tr>
                %endfor

            </tbody>
        </table>
    %endfor

</body>
</html>
</%def>
