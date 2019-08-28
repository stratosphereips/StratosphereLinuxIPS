class WidgetBox{
    constructor({blessed = {}, contrib = {}, screen = {}, grid = {}}){
        this.blessed = blessed;
        this.contrib = contrib;
        this.screen = screen;
        this.grid = grid;
        this.parameters = {width: '50%', height: '50%', tags: true,style:{ focus: { border:{ fg:'magenta'}}}, border: {type: 'line'}};
        this.widget = this.getWidget();
    }

    getWidget(){
        return this.grid.gridObj.set(...this.grid.gridLayout, this.blessed.box, this.parameters);
    }

    
}

class WidgetTree{
    constructor({blessed = {}, contrib = {}, screen = {}, grid = {}}){
        this.blessed = blessed;
        this.contrib = contrib;
        this.screen = screen;
        this.grid = grid;
        this.parameters = { vi:true, style: {border: {fg:'magenta'}}, template: { lines: true }, label: 'default'};
        this.widget = this.getWidget();
    }

    getWidget(){
        return this.grid.gridObj.set(...this.grid.gridLayout, this.contrib.tree, this.parameters);
    }

    
}

module.exports.WidgetBox = WidgetBox;
module.exports.WidgetTree = WidgetTree;